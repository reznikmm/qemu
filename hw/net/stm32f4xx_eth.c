/*
 * STM32F4xx Ethernet MAC (Synopsys DesignWare-derived) emulation
 *
 * Copyright (c) 2026
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 * This is a register-level model of the STM32F4xx "ETH" peripheral as
 * documented in ST RM0090 chapter 34. It implements just enough of the
 * MAC configuration, MDIO and descriptor-based DMA engine to run simple
 * bare-metal drivers (tested against the ada-enet STM32 driver,
 * https://github.com/stcarrez/ada-enet).
 *
 * Unsupported/unimplemented on purpose:
 * - MMC (management counters) block: reads as last-written / zero.
 * - PTP (IEEE1588) block and enhanced (8-word, EDFE=1) descriptors.
 * - Perfect/hash multicast address filtering: all received frames are
 *   handed to the guest, filtering is left to software.
 * - The MDIO/PHY model is a minimal fake PHY that always reports link
 *   up and autonegotiation complete; it does not model any specific
 *   PHY part.
 */

#include "qemu/osdep.h"

#include "hw/core/registerfields.h"
#include "hw/net/mii.h"
#include "hw/net/stm32f4xx_eth.h"
#include "migration/vmstate.h"
#include "net/checksum.h"
#include "net/eth.h"
#include "net/net.h"
#include "qemu/log.h"
#include "qemu/module.h"
#include "system/dma.h"

/* ---- MAC block ---------------------------------------------------- */
REG32(ETH_MACCR,     0x00)
REG32(ETH_MACFFR,    0x04)
REG32(ETH_MACHTHR,   0x08)
REG32(ETH_MACHTLR,   0x0c)
REG32(ETH_MACMIIAR,  0x10)
REG32(ETH_MACMIIDR,  0x14)
REG32(ETH_MACFCR,    0x18)
REG32(ETH_MACVLANTR, 0x1c)
REG32(ETH_MACPMTCSR, 0x2c)
REG32(ETH_MACA0HR,   0x40)
REG32(ETH_MACA0LR,   0x44)

FIELD(ETH_MACCR, RE, 2, 1)
FIELD(ETH_MACCR, TE, 3, 1)

FIELD(ETH_MACMIIAR, MB, 0, 1)
FIELD(ETH_MACMIIAR, MW, 1, 1)
FIELD(ETH_MACMIIAR, CR, 2, 3)
FIELD(ETH_MACMIIAR, MR, 6, 5)
FIELD(ETH_MACMIIAR, PA, 11, 5)

/* ---- DMA block ------------------------------------------------------ */
REG32(ETH_DMABMR,   0x1000)
REG32(ETH_DMATPDR,  0x1004)
REG32(ETH_DMARPDR,  0x1008)
REG32(ETH_DMARDLAR, 0x100c)
REG32(ETH_DMATDLAR, 0x1010)
REG32(ETH_DMASR,    0x1014)
REG32(ETH_DMAOMR,   0x1018)
REG32(ETH_DMAIER,   0x101c)
REG32(ETH_DMAMFBOCR,0x1020)
REG32(ETH_DMACHTDR, 0x1048)
REG32(ETH_DMACHRDR, 0x104c)
REG32(ETH_DMACHTBAR,0x1050)
REG32(ETH_DMACHRBAR,0x1054)

FIELD(ETH_DMABMR, SR, 0, 1)

FIELD(ETH_DMAOMR, SR, 1, 1)
FIELD(ETH_DMAOMR, ST, 13, 1)

FIELD(ETH_DMASR, TS, 0, 1)
FIELD(ETH_DMASR, TBUS, 2, 1)
FIELD(ETH_DMASR, RS, 6, 1)
FIELD(ETH_DMASR, RPS_STATE, 17, 3)
FIELD(ETH_DMASR, TPS_STATE, 20, 3)
FIELD(ETH_DMASR, AIS, 15, 1)
FIELD(ETH_DMASR, NIS, 16, 1)

#define DMA_TPS_SUSPENDED 6
#define DMA_RPS_SUSPENDED 4

/* Bits of DMASR that also exist (at the same position) in DMAIER as the
 * matching "enable" bit, and that we actually generate. */
#define DMA_NIS_BITS (R_ETH_DMASR_TS_MASK | R_ETH_DMASR_RS_MASK)
#define DMA_AIS_BITS (R_ETH_DMASR_TBUS_MASK)

/* ---- Descriptor bit layout (RM0090, "normal descriptor", EDFE = 0) -- */
/* TDES0 */
#define TDES0_OWN  BIT(31)
#define TDES0_IC   BIT(30)
#define TDES0_LS   BIT(29)
#define TDES0_FS   BIT(28)
#define TDES0_DC   BIT(27)
#define TDES0_DP   BIT(26)
#define TDES0_TTSE BIT(25)
#define TDES0_CIC(w)   extract32((w), 22, 2)
#define TDES0_TER  BIT(21)
#define TDES0_TCH  BIT(20)

/* TDES1 */
#define TDES1_TBS1(w) extract32((w), 0, 13)
#define TDES1_TBS2(w) extract32((w), 16, 13)

/* RDES0 */
#define RDES0_OWN BIT(31)
#define RDES0_FS  BIT(9)
#define RDES0_LS  BIT(8)
#define RDES0_FL_SHIFT 16
#define RDES0_FL_MASK  MAKE_64BIT_MASK(16, 14)

/* RDES1 */
#define RDES1_RBS1(w) extract32((w), 0, 13)
#define RDES1_RCH  BIT(14)
#define RDES1_RER  BIT(15)
#define RDES1_RBS2(w) extract32((w), 16, 13)

#define IP_PROTO_ICMP 1

struct STM32F4xxDesc {
    uint32_t d0;
    uint32_t d1;
    uint32_t d2;
    uint32_t d3;
};

static const uint16_t stm32f4xx_eth_phy_reg_init[] = {
    [MII_BMCR]   = MII_BMCR_AUTOEN | MII_BMCR_FD | MII_BMCR_SPEED100,
    [MII_BMSR]   = MII_BMSR_100TX_FD | MII_BMSR_100TX_HD |
                   MII_BMSR_10T_FD | MII_BMSR_10T_HD |
                   MII_BMSR_AUTONEG | MII_BMSR_AN_COMP |
                   MII_BMSR_LINK_ST,
    [MII_PHYID1] = 0x0007,
    [MII_PHYID2] = 0xc0f1,
    [MII_ANAR]   = MII_ANAR_TXFD | MII_ANAR_TX | MII_ANAR_10FD |
                   MII_ANAR_10 | MII_ANAR_CSMACD,
    [MII_ANLPAR] = MII_ANLPAR_ACK | MII_ANLPAR_TXFD | MII_ANLPAR_TX |
                   MII_ANLPAR_10FD | MII_ANLPAR_10 | MII_ANLPAR_CSMACD,
};

static void stm32f4xx_eth_update_irq(STM32F4xxEthState *s)
{
    uint32_t sr = s->regs[R_ETH_DMASR];
    uint32_t ier = s->regs[R_ETH_DMAIER];
    int level;

    if (ier & sr & DMA_NIS_BITS) {
        sr |= R_ETH_DMASR_NIS_MASK;
    }
    if (ier & sr & DMA_AIS_BITS) {
        sr |= R_ETH_DMASR_AIS_MASK;
    }
    s->regs[R_ETH_DMASR] = sr;

    level = !!((sr & ier & R_ETH_DMASR_NIS_MASK) ||
               (sr & ier & R_ETH_DMASR_AIS_MASK));
    qemu_set_irq(s->irq, level);
}

static void stm32f4xx_eth_set_tps(STM32F4xxEthState *s, uint32_t state)
{
    s->regs[R_ETH_DMASR] = deposit32(s->regs[R_ETH_DMASR],
                                      R_ETH_DMASR_TPS_STATE_SHIFT, 3, state);
}

static void stm32f4xx_eth_set_rps(STM32F4xxEthState *s, uint32_t state)
{
    s->regs[R_ETH_DMASR] = deposit32(s->regs[R_ETH_DMASR],
                                      R_ETH_DMASR_RPS_STATE_SHIFT, 3, state);
}

static void stm32f4xx_eth_phy_set_link(STM32F4xxEthState *s, bool up)
{
    if (up) {
        s->phy_regs[0][MII_BMSR] |= MII_BMSR_LINK_ST | MII_BMSR_AN_COMP;
    } else {
        s->phy_regs[0][MII_BMSR] &= ~(MII_BMSR_LINK_ST | MII_BMSR_AN_COMP);
    }
}

static void stm32f4xx_eth_set_link(NetClientState *nc)
{
    STM32F4xxEthState *s = qemu_get_nic_opaque(nc);

    stm32f4xx_eth_phy_set_link(s, !nc->link_down);
}

static void stm32f4xx_eth_mdio_access(STM32F4xxEthState *s, uint32_t v)
{
    bool busy = FIELD_EX32(v, ETH_MACMIIAR, MB);
    uint8_t pa, mr;

    if (busy) {
        pa = FIELD_EX32(v, ETH_MACMIIAR, PA);
        mr = FIELD_EX32(v, ETH_MACMIIAR, MR);
        g_assert(pa < STM32F4XX_ETH_MAX_PHYS);
        g_assert(mr < STM32F4XX_ETH_MAX_PHY_REGS);

        if (FIELD_EX32(v, ETH_MACMIIAR, MW)) {
            uint16_t data = s->regs[R_ETH_MACMIIDR];

            if (mr == MII_BMCR) {
                data &= ~MII_BMCR_RESET;
                if (data & MII_BMCR_ANRESTART) {
                    data &= ~MII_BMCR_ANRESTART;
                    s->phy_regs[pa][MII_BMSR] |= MII_BMSR_AN_COMP;
                }
            }
            s->phy_regs[pa][mr] = data;
        } else {
            s->regs[R_ETH_MACMIIDR] = s->phy_regs[pa][mr];
        }
    }
    /* The transaction completes immediately: MB is never observed set. */
    s->regs[R_ETH_MACMIIAR] = v & ~R_ETH_MACMIIAR_MB_MASK;
}

static bool stm32f4xx_eth_can_receive(NetClientState *nc)
{
    STM32F4xxEthState *s = qemu_get_nic_opaque(nc);

    if (!FIELD_EX32(s->regs[R_ETH_MACCR], ETH_MACCR, RE)) {
        return false;
    }
    if (!FIELD_EX32(s->regs[R_ETH_DMAOMR], ETH_DMAOMR, SR)) {
        return false;
    }
    return true;
}

static int stm32f4xx_eth_read_desc(hwaddr addr, struct STM32F4xxDesc *d)
{
    if (dma_memory_read(&address_space_memory, addr, d, sizeof(*d),
                        MEMTXATTRS_UNSPECIFIED)) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "stm32f4xx_eth: cannot read descriptor @0x%"
                      HWADDR_PRIx "\n", addr);
        return -1;
    }
    d->d0 = le32_to_cpu(d->d0);
    d->d1 = le32_to_cpu(d->d1);
    d->d2 = le32_to_cpu(d->d2);
    d->d3 = le32_to_cpu(d->d3);
    return 0;
}

static int stm32f4xx_eth_write_desc(hwaddr addr, const struct STM32F4xxDesc *d)
{
    struct STM32F4xxDesc le = {
        .d0 = cpu_to_le32(d->d0),
        .d1 = cpu_to_le32(d->d1),
        .d2 = cpu_to_le32(d->d2),
        .d3 = cpu_to_le32(d->d3),
    };

    if (dma_memory_write(&address_space_memory, addr, &le, sizeof(le),
                         MEMTXATTRS_UNSPECIFIED)) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "stm32f4xx_eth: cannot write descriptor @0x%"
                      HWADDR_PRIx "\n", addr);
        return -1;
    }
    return 0;
}

/*
 * ICMP has no pseudo-header and is not covered by net_checksum_calculate()
 * (which only knows about TCP/UDP). The STM32 MAC checksum engine inserts
 * it all the same ("TCP/UDP/ICMP checksum offload" in RM0090), so we need
 * to deal with it ourselves for ICMP (i.e. ping) traffic to work.
 */
static void stm32f4xx_eth_fixup_icmp_checksum(uint8_t *buf, int length)
{
    int l2_hdr_len, ip_hdr_len, ip_len, icmp_len;
    struct ip_header *ip;
    uint16_t csum;

    if (length < (int)sizeof(struct eth_header)) {
        return;
    }
    l2_hdr_len = eth_get_l2_hdr_length(buf);
    length -= l2_hdr_len;
    if (length < (int)sizeof(struct ip_header)) {
        return;
    }

    ip = (struct ip_header *)(buf + l2_hdr_len);
    if (IP_HEADER_VERSION(ip) != IP_HEADER_VERSION_4) {
        return;
    }
    if (ip->ip_p != IP_PROTO_ICMP) {
        return;
    }
    if (IP4_IS_FRAGMENT(ip)) {
        return;
    }

    ip_hdr_len = IP_HDR_GET_LEN(ip);
    ip_len = lduw_be_p(&ip->ip_len);
    if (ip_len < ip_hdr_len || length < ip_len) {
        return;
    }
    icmp_len = ip_len - ip_hdr_len;
    if (icmp_len < 4) {
        return;
    }

    uint8_t *icmp = (uint8_t *)ip + ip_hdr_len;
    /* ICMP checksum is a plain one's complement sum, no pseudo-header. */
    stw_be_p(icmp + 2, 0);
    csum = net_raw_checksum(icmp, icmp_len);
    stw_be_p(icmp + 2, csum);
}

static void stm32f4xx_eth_try_send(STM32F4xxEthState *s)
{
    g_autofree uint8_t *buf = g_malloc(2048);
    size_t buf_size = 2048;
    hwaddr desc_addr;
    struct STM32F4xxDesc d;
    uint32_t frag_addr, frag_len;
    size_t total = 0;
    int csum = 0;

    if (!FIELD_EX32(s->regs[R_ETH_DMAOMR], ETH_DMAOMR, ST)) {
        return;
    }

    if (!s->regs[R_ETH_DMACHTDR]) {
        s->regs[R_ETH_DMACHTDR] = s->regs[R_ETH_DMATDLAR];
    }
    desc_addr = s->regs[R_ETH_DMACHTDR];

    while (true) {
        stm32f4xx_eth_set_tps(s, 1); /* running - fetching descriptor */
        if (stm32f4xx_eth_read_desc(desc_addr, &d)) {
            return;
        }

        if (!(d.d0 & TDES0_OWN)) {
            /* Software owns this descriptor: nothing more to send. */
            stm32f4xx_eth_set_tps(s, DMA_TPS_SUSPENDED);
            s->regs[R_ETH_DMAOMR] =
                s->regs[R_ETH_DMAOMR] & ~R_ETH_DMAOMR_ST_MASK;
            stm32f4xx_eth_update_irq(s);
            return;
        }

        if (d.d0 & TDES0_FS) {
            csum = 0;
            if (TDES0_CIC(d.d0) >= 1) {
                csum |= CSUM_IP;
            }
            if (TDES0_CIC(d.d0) >= 2) {
                csum |= CSUM_TCP | CSUM_UDP;
            }
            total = 0;
        }

        frag_addr = d.d2;
        frag_len = TDES1_TBS1(d.d1);
        if (frag_len) {
            if (total + frag_len > buf_size) {
                buf_size = total + frag_len;
                buf = g_realloc(buf, buf_size);
            }
            if (dma_memory_read(&address_space_memory, frag_addr,
                                buf + total, frag_len,
                                MEMTXATTRS_UNSPECIFIED)) {
                qemu_log_mask(LOG_GUEST_ERROR,
                              "stm32f4xx_eth: tx buffer read failed @0x%x\n",
                              frag_addr);
                return;
            }
            total += frag_len;
        }

        /* This driver never uses a second buffer per descriptor (TBS2 is
         * always zero) but handle it for robustness. */
        frag_len = TDES1_TBS2(d.d1);
        if (frag_len) {
            frag_addr = d.d3;
            if (total + frag_len > buf_size) {
                buf_size = total + frag_len;
                buf = g_realloc(buf, buf_size);
            }
            if (dma_memory_read(&address_space_memory, frag_addr,
                                buf + total, frag_len,
                                MEMTXATTRS_UNSPECIFIED)) {
                return;
            }
            total += frag_len;
        }

        if (d.d0 & TDES0_LS) {
            net_checksum_calculate(buf, total, csum);
            if (csum & CSUM_IP) {
                stm32f4xx_eth_fixup_icmp_checksum(buf, total);
            }
            qemu_send_packet(qemu_get_queue(s->nic), buf, total);
        }

        d.d0 &= ~TDES0_OWN;
        stm32f4xx_eth_write_desc(desc_addr, &d);

        if (d.d0 & TDES0_TER) {
            desc_addr = s->regs[R_ETH_DMATDLAR];
        } else if (d.d0 & TDES0_TCH) {
            desc_addr = d.d3;
        } else {
            desc_addr += sizeof(d);
        }
        s->regs[R_ETH_DMACHTDR] = desc_addr;

        if (d.d0 & TDES0_IC) {
            s->regs[R_ETH_DMASR] |= R_ETH_DMASR_TS_MASK;
        }
        stm32f4xx_eth_update_irq(s);
    }
}

static ssize_t stm32f4xx_eth_receive(NetClientState *nc, const uint8_t *buf,
                                     size_t len)
{
    STM32F4xxEthState *s = qemu_get_nic_opaque(nc);
    hwaddr desc_addr;
    struct STM32F4xxDesc d;
    uint32_t buf_len, buf_addr;
    size_t left = len;
    bool first = true;

    if (!stm32f4xx_eth_can_receive(nc)) {
        return -1;
    }

    if (!s->regs[R_ETH_DMACHRDR]) {
        s->regs[R_ETH_DMACHRDR] = s->regs[R_ETH_DMARDLAR];
    }
    desc_addr = s->regs[R_ETH_DMACHRDR];

    stm32f4xx_eth_set_rps(s, 1); /* running - fetching descriptor */
    if (stm32f4xx_eth_read_desc(desc_addr, &d)) {
        stm32f4xx_eth_set_rps(s, DMA_RPS_SUSPENDED);
        return -1;
    }

    if (!(d.d0 & RDES0_OWN)) {
        /* No free descriptor: drop the frame, let software recover. */
        stm32f4xx_eth_set_rps(s, DMA_RPS_SUSPENDED);
        stm32f4xx_eth_update_irq(s);
        return len;
    }

    while (left > 0) {
        buf_len = RDES1_RBS1(d.d1);
        buf_addr = d.d2;
        if (buf_len > left) {
            buf_len = left;
        }
        if (buf_len &&
            dma_memory_write(&address_space_memory, buf_addr,
                             buf + (len - left), buf_len,
                             MEMTXATTRS_UNSPECIFIED)) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "stm32f4xx_eth: rx buffer write failed @0x%x\n",
                          buf_addr);
            return -1;
        }
        left -= buf_len;

        d.d0 = 0;
        if (first) {
            d.d0 |= RDES0_FS;
            first = false;
        }
        if (left == 0) {
            d.d0 |= RDES0_LS;
            d.d0 = deposit32(d.d0, RDES0_FL_SHIFT, 14, len);
        }
        /* Give the descriptor back to software. */
        stm32f4xx_eth_write_desc(desc_addr, &d);

        if (left == 0) {
            break;
        }

        if (d.d1 & RDES1_RER) {
            desc_addr = s->regs[R_ETH_DMARDLAR];
        } else if (d.d1 & RDES1_RCH) {
            desc_addr = d.d3;
        } else {
            desc_addr += sizeof(d);
        }
        if (stm32f4xx_eth_read_desc(desc_addr, &d) || !(d.d0 & RDES0_OWN)) {
            stm32f4xx_eth_set_rps(s, DMA_RPS_SUSPENDED);
            stm32f4xx_eth_update_irq(s);
            return len;
        }
    }

    if (d.d1 & RDES1_RER) {
        desc_addr = s->regs[R_ETH_DMARDLAR];
    } else if (d.d1 & RDES1_RCH) {
        desc_addr = d.d3;
    } else {
        desc_addr += sizeof(d);
    }
    s->regs[R_ETH_DMACHRDR] = desc_addr;

    stm32f4xx_eth_set_rps(s, 3); /* running - waiting for a packet */
    s->regs[R_ETH_DMASR] |= R_ETH_DMASR_RS_MASK;
    stm32f4xx_eth_update_irq(s);
    return len;
}

static void stm32f4xx_eth_cleanup(NetClientState *nc)
{
}

static uint64_t stm32f4xx_eth_read(void *opaque, hwaddr offset, unsigned size)
{
    STM32F4xxEthState *s = opaque;

    if (offset >= STM32F4XX_ETH_REG_SIZE) {
        return 0;
    }
    return s->regs[offset / sizeof(uint32_t)];
}

static void stm32f4xx_eth_write(void *opaque, hwaddr offset,
                                uint64_t val, unsigned size)
{
    STM32F4xxEthState *s = opaque;
    uint32_t v = val;

    if (offset >= STM32F4XX_ETH_REG_SIZE) {
        return;
    }

    switch (offset) {
    case A_ETH_MACMIIAR:
        stm32f4xx_eth_mdio_access(s, v);
        return;

    case A_ETH_MACA0HR:
        s->regs[R_ETH_MACA0HR] = v;
        s->conf.macaddr.a[0] = v;
        s->conf.macaddr.a[1] = v >> 8;
        return;

    case A_ETH_MACA0LR:
        s->regs[R_ETH_MACA0LR] = v;
        s->conf.macaddr.a[2] = v;
        s->conf.macaddr.a[3] = v >> 8;
        s->conf.macaddr.a[4] = v >> 16;
        s->conf.macaddr.a[5] = v >> 24;
        return;

    case A_ETH_DMABMR:
        s->regs[R_ETH_DMABMR] = v;
        if (FIELD_EX32(v, ETH_DMABMR, SR)) {
            /* Software reset completes instantly. */
            s->regs[R_ETH_DMABMR] &= ~R_ETH_DMABMR_SR_MASK;
            s->regs[R_ETH_DMASR] = 0;
            s->regs[R_ETH_DMACHTDR] = 0;
            s->regs[R_ETH_DMACHRDR] = 0;
        }
        return;

    case A_ETH_DMATPDR:
        /* Poll demand: kick the transmit engine, value is ignored. */
        stm32f4xx_eth_try_send(s);
        return;

    case A_ETH_DMARPDR:
        /* Poll demand: value is ignored, just make sure we are able to
         * pick up any packet that was queued while we had no free
         * descriptor. */
        qemu_flush_queued_packets(qemu_get_queue(s->nic));
        return;

    case A_ETH_DMAOMR:
        s->regs[R_ETH_DMAOMR] = v;
        if (FIELD_EX32(v, ETH_DMAOMR, ST)) {
            stm32f4xx_eth_try_send(s);
        } else {
            stm32f4xx_eth_set_tps(s, 0);
        }
        if (FIELD_EX32(v, ETH_DMAOMR, SR)) {
            qemu_flush_queued_packets(qemu_get_queue(s->nic));
        } else {
            stm32f4xx_eth_set_rps(s, 0);
        }
        stm32f4xx_eth_update_irq(s);
        return;

    case A_ETH_DMASR:
        /* Write-1-to-clear. */
        s->regs[R_ETH_DMASR] &= ~v;
        stm32f4xx_eth_update_irq(s);
        return;

    /* Read-only / status registers: ignore writes. */
    case A_ETH_DMACHTBAR:
    case A_ETH_DMACHRBAR:
    case A_ETH_DMACHRDR:
    case A_ETH_DMAMFBOCR:
        return;

    case A_ETH_DMACHTDR:
        /*
         * Normally read-only, but some bare-metal drivers (e.g. ada-enet)
         * write it to push the DMA engine's current descriptor pointer
         * back after observing a "suspended" transmit state, instead of
         * reprogramming DMATDLAR. Honour that so such drivers work.
         */
        s->regs[R_ETH_DMACHTDR] = v;
        return;

    default:
        s->regs[offset / sizeof(uint32_t)] = v;
        return;
    }
}

static const MemoryRegionOps stm32f4xx_eth_ops = {
    .read = stm32f4xx_eth_read,
    .write = stm32f4xx_eth_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static NetClientInfo stm32f4xx_eth_net_info = {
    .type = NET_CLIENT_DRIVER_NIC,
    .size = sizeof(NICState),
    .can_receive = stm32f4xx_eth_can_receive,
    .receive = stm32f4xx_eth_receive,
    .cleanup = stm32f4xx_eth_cleanup,
    .link_status_changed = stm32f4xx_eth_set_link,
};

static void stm32f4xx_eth_reset(DeviceState *dev)
{
    STM32F4xxEthState *s = STM32F4XX_ETH(dev);

    memset(s->regs, 0, sizeof(s->regs));
    memset(s->phy_regs, 0, sizeof(s->phy_regs));
    memcpy(s->phy_regs[0], stm32f4xx_eth_phy_reg_init,
           sizeof(stm32f4xx_eth_phy_reg_init));

    s->regs[R_ETH_MACA0HR] = 0x8000 | (s->conf.macaddr.a[1] << 8) |
                              s->conf.macaddr.a[0];
    s->regs[R_ETH_MACA0LR] = s->conf.macaddr.a[5] << 24 |
                              s->conf.macaddr.a[4] << 16 |
                              s->conf.macaddr.a[3] << 8 |
                              s->conf.macaddr.a[2];
}

static void stm32f4xx_eth_realize(DeviceState *dev, Error **errp)
{
    STM32F4xxEthState *s = STM32F4XX_ETH(dev);
    SysBusDevice *sbd = SYS_BUS_DEVICE(dev);

    memory_region_init_io(&s->iomem, OBJECT(s), &stm32f4xx_eth_ops, s,
                          TYPE_STM32F4XX_ETH, STM32F4XX_ETH_REG_SIZE);
    sysbus_init_mmio(sbd, &s->iomem);
    sysbus_init_irq(sbd, &s->irq);

    qemu_macaddr_default_if_unset(&s->conf.macaddr);
    s->nic = qemu_new_nic(&stm32f4xx_eth_net_info, &s->conf,
                          object_get_typename(OBJECT(dev)), dev->id,
                          &dev->mem_reentrancy_guard, s);
    qemu_format_nic_info_str(qemu_get_queue(s->nic), s->conf.macaddr.a);
}

static void stm32f4xx_eth_unrealize(DeviceState *dev)
{
    STM32F4xxEthState *s = STM32F4XX_ETH(dev);

    qemu_del_nic(s->nic);
}

static const VMStateDescription stm32f4xx_eth_vmstate = {
    .name = TYPE_STM32F4XX_ETH,
    .version_id = 0,
    .minimum_version_id = 0,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32_ARRAY(regs, STM32F4xxEthState, STM32F4XX_ETH_NR_REGS),
        VMSTATE_END_OF_LIST(),
    },
};

static const Property stm32f4xx_eth_properties[] = {
    DEFINE_NIC_PROPERTIES(STM32F4xxEthState, conf),
};

static void stm32f4xx_eth_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    set_bit(DEVICE_CATEGORY_NETWORK, dc->categories);
    dc->desc = "STM32F4xx Ethernet MAC";
    dc->realize = stm32f4xx_eth_realize;
    dc->unrealize = stm32f4xx_eth_unrealize;
    device_class_set_legacy_reset(dc, stm32f4xx_eth_reset);
    dc->vmsd = &stm32f4xx_eth_vmstate;
    device_class_set_props(dc, stm32f4xx_eth_properties);
}

static const TypeInfo stm32f4xx_eth_types[] = {
    {
        .name = TYPE_STM32F4XX_ETH,
        .parent = TYPE_SYS_BUS_DEVICE,
        .instance_size = sizeof(STM32F4xxEthState),
        .class_init = stm32f4xx_eth_class_init,
    },
};
DEFINE_TYPES(stm32f4xx_eth_types)
