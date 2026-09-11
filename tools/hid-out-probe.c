#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/hid/IOHIDKeys.h>
#include <IOKit/hid/IOHIDManager.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static int parse_usb_id(const char *text, int *value) {
    char *end = NULL;
    unsigned long parsed = strtoul(text, &end, 0);
    if (text == end || *end != '\0' || parsed == 0 || parsed >= 0xffff) {
        return 0;
    }
    *value = (int)parsed;
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s VID PID\n", argv[0]);
        return 2;
    }

    int vendor_id = 0;
    int product_id = 0;
    if (!parse_usb_id(argv[1], &vendor_id) ||
        !parse_usb_id(argv[2], &product_id)) {
        fputs("VID and PID must be integers from 1 through 0xfffe\n", stderr);
        return 2;
    }

    IOHIDManagerRef manager =
        IOHIDManagerCreate(kCFAllocatorDefault, kIOHIDOptionsTypeNone);
    if (manager == NULL) {
        fputs("failed to create IOHIDManager\n", stderr);
        return 1;
    }

    CFMutableDictionaryRef matching = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    CFNumberRef vendor =
        CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &vendor_id);
    CFNumberRef product =
        CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &product_id);
    CFDictionarySetValue(matching, CFSTR(kIOHIDVendorIDKey), vendor);
    CFDictionarySetValue(matching, CFSTR(kIOHIDProductIDKey), product);
    IOHIDManagerSetDeviceMatching(manager, matching);

    IOReturn result = IOHIDManagerOpen(manager, kIOHIDOptionsTypeNone);
    if (result != kIOReturnSuccess) {
        fprintf(stderr, "failed to open IOHIDManager: 0x%08x\n", result);
        return 1;
    }

    CFSetRef device_set = IOHIDManagerCopyDevices(manager);
    if (device_set == NULL || CFSetGetCount(device_set) != 1) {
        fputs("expected exactly one matching HID device\n", stderr);
        return 1;
    }

    const void *devices[1];
    CFSetGetValues(device_set, devices);
    IOHIDDeviceRef device = (IOHIDDeviceRef)devices[0];
    result = IOHIDDeviceOpen(device, kIOHIDOptionsTypeNone);
    if (result != kIOReturnSuccess) {
        fprintf(stderr, "failed to open HID device: 0x%08x\n", result);
        return 1;
    }

    uint8_t report[64] = {
        0xff, 0xff, 0xff, 0xff, 0x86, 0x00, 0x08,
        0x52, 0x49, 0x53, 0x53, 0x4f, 0x4b, 0x45, 0x59,
    };
    result = IOHIDDeviceSetReport(device, kIOHIDReportTypeOutput, 0, report,
                                  sizeof(report));

    IOHIDDeviceClose(device, kIOHIDOptionsTypeNone);
    CFRelease(device_set);
    IOHIDManagerClose(manager, kIOHIDOptionsTypeNone);
    CFRelease(product);
    CFRelease(vendor);
    CFRelease(matching);
    CFRelease(manager);

    if (result != kIOReturnSuccess) {
        fprintf(stderr, "64-byte HID OUT failed: 0x%08x\n", result);
        return 1;
    }

    puts("sent one 64-byte CTAPHID_INIT report");
    return 0;
}
