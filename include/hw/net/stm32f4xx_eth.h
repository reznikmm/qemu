/*
 * STM32F4xx Ethernet MAC (Synopsys DesignWare-derived) emulation
 *
 * Copyright (c) 2026
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 * Register map is taken from ST RM0090 chapter 34 ("Ethernet (ETH):
 * media access control (MAC) with DMA controller"). The descriptor bit
 * layout matches the "normal descriptor" format used by the reference
 * manual and by third-party bare-metal drivers such as ada-enet
 * (https://github.com/stcarrez/ada-enet).
 */

#ifndef HW_NET_STM32F4XX_ETH_H
#define HW_NET_STM32F4XX_ETH_H

#include "hw/core/irq.h"
#include "hw/core/sysbus.h"
#include "net/net.h"
#include "qom/object.h"

#define TYPE_STM32F4XX_ETH "stm32f4xx-eth"
OBJECT_DECLARE_SIMPLE_TYPE(STM32F4xxEthState, STM32F4XX_ETH)

/* Total size of the ETH register block (MAC + MMC + PTP + DMA) */
#define STM32F4XX_ETH_REG_SIZE   0x1400
#define STM32F4XX_ETH_NR_REGS    (STM32F4XX_ETH_REG_SIZE / sizeof(uint32_t))

#define STM32F4XX_ETH_MAX_PHYS      32
#define STM32F4XX_ETH_MAX_PHY_REGS  32

struct STM32F4xxEthState {
    SysBusDevice parent_obj;

    MemoryRegion iomem;
    qemu_irq irq;

    NICState *nic;
    NICConf conf;

    uint32_t regs[STM32F4XX_ETH_NR_REGS];
    uint16_t phy_regs[STM32F4XX_ETH_MAX_PHYS][STM32F4XX_ETH_MAX_PHY_REGS];
};

#endif /* HW_NET_STM32F4XX_ETH_H */
