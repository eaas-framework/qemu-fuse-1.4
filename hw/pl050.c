/*
 * Arm PrimeCell PL050 Keyboard / Mouse Interface
 *
 * Copyright (c) 2006-2007 CodeSourcery.
 * Written by Paul Brook
 *
 * This code is licensed under the GPL.
 */

#include "sysbus.h"
#include "ps2.h"

typedef struct {
    SysBusDevice busdev;
    MemoryRegion iomem;
    void *dev;
    uint32_t cr;
    uint32_t clk;
    uint32_t last;
    int pending;
    qemu_irq irq;
    int is_mouse;
} pl050_state;

static const VMStateDescription vmstate_pl050 = {
    .name = "pl050",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(cr, pl050_state),
        VMSTATE_UINT32(clk, pl050_state),
        VMSTATE_UINT32(last, pl050_state),
        VMSTATE_INT32(pending, pl050_state),
        VMSTATE_INT32(is_mouse, pl050_state),
        VMSTATE_END_OF_LIST()
    }
};

#define PL050_TXEMPTY         (1 << 6)
#define PL050_TXBUSY          (1 << 5)
#define PL050_RXFULL          (1 << 4)
#define PL050_RXBUSY          (1 << 3)
#define PL050_RXPARITY        (1 << 2)
#define PL050_KMIC            (1 << 1)
#define PL050_KMID            (1 << 0)

static const unsigned char pl050_id[] =
{ 0x50, 0x10, 0x04, 0x00, 0x0d, 0xf0, 0x05, 0xb1 };

static void pl050_update(void *opaque, int level)
{
    pl050_state *s = (pl050_state *)opaque;
    int raise;

    s->pending = level;
    raise = (s->pending && (s->cr & 0x10) != 0)
            || (s->cr & 0x08) != 0;
    qemu_set_irq(s->irq, raise);
}

static uint64_t pl050_read(void *opaque, hwaddr offset,
                           unsigned size)
{
    pl050_state *s = (pl050_state *)opaque;
    if (offset >= 0xfe0 && offset < 0x1000)
        return pl050_id[(offset - 0xfe0) >> 2];

    switch (offset >> 2) {
    case 0: /* KMICR */
        return s->cr;
    case 1: /* KMISTAT */
        {
            uint8_t val;
            uint32_t stat;

            val = s->last;
            val = val ^ (val >> 4);
            val = val ^ (val >> 2);
            val = (val ^ (val >> 1)) & 1;

            stat = PL050_TXEMPTY;
            if (val)
                stat |= PL050_RXPARITY;
            if (s->pending)
                stat |= PL050_RXFULL;

            return stat;
        }
    case 2: /* KMIDATA */
        if (s->pending)
            s->last = ps2_read_data(s->dev);
        return s->last;
    case 3: /* KMICLKDIV */
        return s->clk;
    case 4: /* KMIIR */
        return s->pending | 2;
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "pl050_read: Bad offset %x\n", (int)offset);
        return 0;
    }
}

static void pl050_write(void *opaque, hwaddr offset,
                        uint64_t value, unsigned size)
{
    pl050_state *s = (pl050_state *)opaque;
    switch (offset >> 2) {
    case 0: /* KMICR */
        s->cr = value;
        pl050_update(s, s->pending);
        /* ??? Need to implement the enable/disable bit.  */
        break;
    case 2: /* KMIDATA */
        /* ??? This should toggle the TX interrupt line.  */
        /* ??? This means kbd/mouse can block each other.  */
        if (s->is_mouse) {
            ps2_write_mouse(s->dev, value);
        } else {
            ps2_write_keyboard(s->dev, value);
        }
        break;
    case 3: /* KMICLKDIV */
        s->clk = value;
        return;
    default:
        qemu_log_mask(LOG_GUEST_ERROR,
                      "pl050_write: Bad offset %x\n", (int)offset);
    }
}
static const MemoryRegionOps pl050_ops = {
    .read = pl050_read,
    .write = pl050_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static int pl050_init(SysBusDevice *dev, int is_mouse)
{
    pl050_state *s = FROM_SYSBUS(pl050_state, dev);

    memory_region_init_io(&s->iomem, &pl050_ops, s, "pl050", 0x1000);
    sysbus_init_mmio(dev, &s->iomem);
    sysbus_init_irq(dev, &s->irq);
    s->is_mouse = is_mouse;
    if (s->is_mouse)
        s->dev = ps2_mouse_init(pl050_update, s);
    else
        s->dev = ps2_kbd_init(pl050_update, s);
    return 0;
}

static int pl050_init_keyboard(SysBusDevice *dev)
{
    return pl050_init(dev, 0);
}

static int pl050_init_mouse(SysBusDevice *dev)
{
    return pl050_init(dev, 1);
}

static void pl050_kbd_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    SysBusDeviceClass *k = SYS_BUS_DEVICE_CLASS(klass);

    k->init = pl050_init_keyboard;
    dc->vmsd = &vmstate_pl050;
}

static const TypeInfo pl050_kbd_info = {
    .name          = "pl050_keyboard",
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(pl050_state),
    .class_init    = pl050_kbd_class_init,
};

static void pl050_mouse_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    SysBusDeviceClass *k = SYS_BUS_DEVICE_CLASS(klass);

    k->init = pl050_init_mouse;
    dc->vmsd = &vmstate_pl050;
}

static const TypeInfo pl050_mouse_info = {
    .name          = "pl050_mouse",
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(pl050_state),
    .class_init    = pl050_mouse_class_init,
};

static void pl050_register_types(void)
{
    type_register_static(&pl050_kbd_info);
    type_register_static(&pl050_mouse_info);
}

type_init(pl050_register_types)
