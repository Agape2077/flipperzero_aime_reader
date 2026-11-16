#include "aime_reader.h"
#include <cli/cli_vcp.h>
#include <furi_hal_usb.h>
#include <furi_hal_usb_cdc.h>
#include <furi_hal_nfc.h>
#include <nfc/nfc.h>
#include <nfc/nfc_poller.h>
#include <nfc/protocols/felica/felica.h>
#include <nfc/protocols/felica/felica_poller.h>
#include <nfc/protocols/iso14443_3a/iso14443_3a_poller.h>
#include <nfc/protocols/mf_classic/mf_classic.h>
#include <nfc/protocols/mf_classic/mf_classic_poller.h>
#include <notification/notification_messages.h>
#include <storage/storage.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CDC_IF_NUM 0

// 官方 aic.c S-PAD 0 解密表与参数
#define AIC_N_TABLES      8
#define AIC_ITERATION_ADD 5

static const uint8_t aic_s_box[9][256] = {
    {0x24, 0x3c, 0xba, 0x36, 0xe3, 0x85, 0xa4, 0xd0, 0x93, 0x43, 0x73, 0xb9, 0x70, 0x6e, 0xc9,
     0xf1, 0x10, 0x0e, 0x9b, 0x2c, 0x97, 0xe7, 0x0b, 0x63, 0x6c, 0x29, 0x20, 0xfe, 0x86, 0xf3,
     0xe1, 0xf5, 0xf6, 0x9f, 0xb6, 0x16, 0x04, 0x7b, 0x8f, 0xab, 0xb1, 0x39, 0x2a, 0x1b, 0xeb,
     0x5c, 0xa8, 0xac, 0x38, 0x11, 0x12, 0x5f, 0x89, 0x3e, 0x7d, 0xca, 0xec, 0x53, 0xdb, 0x6d,
     0x1e, 0xd2, 0x81, 0x78, 0x96, 0x46, 0xff, 0xf9, 0x54, 0x1c, 0x28, 0x7a, 0x4f, 0xd3, 0xc0,
     0xdc, 0xc1, 0x6a, 0xf2, 0xbc, 0xcb, 0x57, 0xfd, 0x4a, 0xe4, 0xf0, 0xb2, 0xc7, 0x95, 0x40,
     0x62, 0x52, 0x41, 0xe2, 0xad, 0x49, 0xa6, 0xb5, 0x1f, 0x02, 0xc8, 0xda, 0x92, 0xe5, 0xb0,
     0xc5, 0x64, 0x76, 0x48, 0x21, 0xde, 0x0f, 0x45, 0x58, 0x4c, 0xdf, 0xa7, 0x84, 0xcf, 0xd5,
     0x15, 0x4e, 0x27, 0x80, 0x6b, 0x7f, 0xfc, 0x44, 0x71, 0x47, 0x22, 0xdd, 0x30, 0x0c, 0xa1,
     0x3b, 0xe0, 0x37, 0xa0, 0x35, 0x23, 0x90, 0x32, 0x74, 0xbf, 0x8d, 0xc2, 0xea, 0xd6, 0x50,
     0xbb, 0xd9, 0xc4, 0x83, 0xb4, 0x31, 0x68, 0x55, 0x8b, 0x5d, 0xf4, 0x72, 0x18, 0xb7, 0xef,
     0xf7, 0x98, 0x2d, 0x01, 0x03, 0x61, 0xcc, 0x0a, 0x8e, 0x13, 0x00, 0xe8, 0x14, 0xaf, 0x09,
     0x51, 0x75, 0xa5, 0x2f, 0x1d, 0x0d, 0x65, 0x8a, 0xcd, 0x66, 0x07, 0x3d, 0x05, 0xd8, 0x4b,
     0xe9, 0x9d, 0x99, 0x7c, 0x91, 0xd1, 0xb8, 0x19, 0xc3, 0x2b, 0x42, 0x69, 0x88, 0xc6, 0x79,
     0x17, 0x3a, 0x4d, 0x5b, 0xa2, 0x5a, 0xfb, 0x25, 0x3f, 0xbd, 0xf8, 0xed, 0xce, 0xe6, 0x87,
     0xa3, 0x26, 0xa9, 0x2e, 0xbe, 0x94, 0x08, 0x7e, 0x67, 0x60, 0x8c, 0x9c, 0x5e, 0x6f, 0xb3,
     0x9e, 0x06, 0xfa, 0x82, 0xae, 0xee, 0x59, 0x77, 0xd7, 0x1a, 0x9a, 0x34, 0xd4, 0x56, 0xaa,
     0x33},
    {0xf9, 0x81, 0x7c, 0x00, 0xb9, 0x30, 0x37, 0xd5, 0x90, 0x51, 0x6e, 0xf0, 0xb2, 0x06, 0xfb,
     0xcd, 0x39, 0x14, 0x5f, 0xf8, 0x1b, 0xc7, 0x4a, 0x82, 0x70, 0x8c, 0x92, 0x1d, 0xea, 0xc3,
     0x4e, 0xc8, 0x12, 0xe6, 0xb6, 0x10, 0xd3, 0x2f, 0x95, 0x84, 0x25, 0x42, 0xa5, 0x72, 0xe5,
     0x8f, 0x55, 0xef, 0x86, 0xa2, 0x53, 0xae, 0xed, 0x26, 0x20, 0x47, 0xde, 0x78, 0x68, 0x28,
     0xe4, 0x45, 0xcc, 0x35, 0xbc, 0x3e, 0xbb, 0x8e, 0xc0, 0xbe, 0x34, 0xaf, 0xa6, 0x09, 0x64,
     0x01, 0x7b, 0x44, 0xf5, 0xf3, 0xb1, 0x3f, 0xa4, 0xb3, 0x32, 0x80, 0xc9, 0x4f, 0x6f, 0x40,
     0xbf, 0x21, 0x4c, 0x74, 0xe1, 0x11, 0x5e, 0xeb, 0x3d, 0x71, 0x2e, 0x9d, 0x62, 0x75, 0xd4,
     0x16, 0x48, 0x77, 0x13, 0x67, 0xad, 0x6b, 0x5d, 0x07, 0x87, 0xf7, 0xa8, 0x9a, 0x59, 0x76,
     0x8b, 0x9b, 0x1e, 0xd8, 0xee, 0xaa, 0xe9, 0x99, 0x2d, 0xc5, 0x97, 0xf1, 0xa7, 0x83, 0xfc,
     0xca, 0xdc, 0xba, 0xb8, 0x4b, 0xe8, 0x89, 0x17, 0x05, 0x0b, 0xa0, 0x65, 0x23, 0xd1, 0xce,
     0x36, 0x03, 0xd7, 0xe0, 0xf2, 0x91, 0xdf, 0x0e, 0x9c, 0x2c, 0x0d, 0x66, 0xd6, 0x73, 0x58,
     0x5c, 0xb4, 0x0a, 0x4d, 0xc2, 0x3b, 0xd2, 0xb7, 0xe2, 0xac, 0x33, 0xdb, 0x60, 0x27, 0xbd,
     0x56, 0x43, 0x24, 0x04, 0x02, 0x8d, 0x7d, 0x7f, 0xf6, 0xb5, 0xf4, 0xfd, 0xdd, 0x5b, 0xec,
     0x79, 0xc4, 0x22, 0x1f, 0xa1, 0x88, 0x54, 0xe7, 0x19, 0x98, 0x94, 0x7e, 0x31, 0xa3, 0x29,
     0xe3, 0x5a, 0xcb, 0x6a, 0xb0, 0xcf, 0x6d, 0x93, 0x6c, 0x7a, 0x08, 0xa9, 0x3c, 0x1c, 0xd0,
     0x63, 0x50, 0xc6, 0x85, 0x38, 0xc1, 0x41, 0x49, 0xab, 0x61, 0x52, 0x2a, 0x9f, 0xd9, 0x18,
     0x1a, 0x57, 0x46, 0x2b, 0x69, 0xda, 0xfa, 0xff, 0x0f, 0x15, 0x96, 0x3a, 0x8a, 0xfe, 0x9e,
     0x0c},
    {0x11, 0xa2, 0x9a, 0xc3, 0x94, 0xa0, 0x51, 0x01, 0x5b, 0xf7, 0xd1, 0x30, 0xee, 0x1f, 0x06,
     0xd5, 0x77, 0x67, 0xd3, 0xc1, 0x6e, 0xe7, 0x6a, 0x1a, 0xa4, 0x8e, 0x9f, 0x65, 0x66, 0xd6,
     0x0c, 0x2d, 0xc6, 0xe4, 0x69, 0xb7, 0x56, 0x5a, 0x57, 0x60, 0xfc, 0x79, 0x1e, 0xe1, 0x16,
     0x52, 0xf0, 0x07, 0xd0, 0xcd, 0xca, 0x78, 0xc9, 0x8b, 0xb3, 0x88, 0x27, 0xf6, 0xe0, 0xc0,
     0x84, 0xcf, 0x2f, 0xa3, 0x04, 0x00, 0x80, 0x40, 0xa7, 0xfa, 0x75, 0x9d, 0x4b, 0x89, 0x46,
     0x22, 0x28, 0x37, 0x34, 0x13, 0xff, 0x20, 0xb4, 0xda, 0x08, 0x26, 0x6c, 0x8f, 0xf2, 0x5d,
     0x7b, 0x73, 0x5c, 0x4c, 0x90, 0x71, 0x41, 0x8a, 0x9e, 0xbb, 0x12, 0xe8, 0x55, 0x6d, 0x2a,
     0x25, 0x4a, 0xaf, 0xbd, 0x95, 0x19, 0xa5, 0x31, 0xba, 0xad, 0xd9, 0xc5, 0xa6, 0x6b, 0x83,
     0xc4, 0xb6, 0xa9, 0xcc, 0xf9, 0xa1, 0xb1, 0x7a, 0xdc, 0xc7, 0xdb, 0x2e, 0x7e, 0x7f, 0x8d,
     0x4e, 0x62, 0x0f, 0x03, 0x39, 0xfd, 0xb8, 0xd4, 0x18, 0xc2, 0xec, 0x61, 0x02, 0x53, 0x1c,
     0x3b, 0x7d, 0xbc, 0x1d, 0x59, 0xf5, 0x8c, 0x98, 0xf1, 0x6f, 0x93, 0x85, 0xf8, 0x2c, 0x74,
     0xd8, 0x5e, 0x4d, 0x97, 0xab, 0x87, 0x82, 0x0a, 0x21, 0x42, 0x5f, 0x0d, 0x58, 0x33, 0x44,
     0x3a, 0xdd, 0xe9, 0xfb, 0x50, 0x47, 0xc8, 0xd7, 0x81, 0x9b, 0xe5, 0x1b, 0x17, 0x54, 0x86,
     0x2b, 0xef, 0xf4, 0x29, 0x32, 0x0e, 0x7c, 0x23, 0x15, 0xeb, 0xe6, 0x3c, 0x35, 0xe2, 0x96,
     0x68, 0x3f, 0x0b, 0x43, 0xce, 0xde, 0x9c, 0xbe, 0x4f, 0x45, 0x72, 0x76, 0xb5, 0x10, 0xe3,
     0xdf, 0x92, 0xd2, 0xa8, 0x48, 0x91, 0xb9, 0xac, 0xbf, 0x49, 0xb2, 0x99, 0x64, 0x70, 0xea,
     0xf3, 0x3e, 0x63, 0x14, 0xae, 0xed, 0xaa, 0x24, 0xfe, 0x3d, 0xcb, 0xb0, 0x09, 0x38, 0x36,
     0x05},
    {0xc4, 0xf0, 0x28, 0x49, 0x55, 0x4a, 0xf5, 0xfd, 0x75, 0xaf, 0x20, 0x69, 0xc8, 0x43, 0x86,
     0x6b, 0xc9, 0xa8, 0xc6, 0x54, 0x4c, 0xdd, 0x02, 0x5b, 0xe8, 0x9b, 0x59, 0x77, 0x34, 0xd7,
     0xc0, 0x51, 0x5f, 0xf3, 0x7e, 0xd4, 0xf1, 0x90, 0x81, 0xce, 0x19, 0x8a, 0x78, 0x33, 0xcd,
     0x97, 0x8c, 0xd6, 0x6a, 0x4b, 0x8f, 0xa4, 0x80, 0xdc, 0x1a, 0x17, 0x14, 0xc5, 0x07, 0x87,
     0x66, 0xad, 0x9d, 0x85, 0xb2, 0xf8, 0x8d, 0x98, 0xdf, 0x3e, 0x1f, 0x3f, 0x64, 0x58, 0x40,
     0xac, 0x6c, 0x5c, 0x08, 0x5d, 0x53, 0xba, 0xff, 0xd2, 0xa9, 0x2c, 0x25, 0xab, 0xe4, 0x32,
     0x38, 0x9a, 0xf9, 0xcb, 0xc2, 0x91, 0x67, 0xd0, 0xe3, 0x22, 0x29, 0x2d, 0x92, 0x48, 0xb4,
     0x0e, 0x99, 0x05, 0xa3, 0x6f, 0x0a, 0x15, 0xef, 0xd5, 0x10, 0x4f, 0xd8, 0xf6, 0x00, 0xe6,
     0x46, 0x2b, 0x31, 0x57, 0x83, 0x94, 0xae, 0x03, 0xeb, 0x8e, 0x13, 0x24, 0xa1, 0x1e, 0x5e,
     0xd1, 0x26, 0xd9, 0xa7, 0xca, 0x36, 0x6e, 0x71, 0x37, 0xee, 0xb1, 0xfa, 0x7c, 0x76, 0x06,
     0xb8, 0x23, 0xbe, 0x21, 0xbc, 0x9e, 0xc1, 0xda, 0x7a, 0x3b, 0x62, 0x27, 0x7b, 0xb0, 0xe5,
     0x63, 0x18, 0x82, 0x7f, 0x0f, 0xed, 0xa0, 0x2a, 0x9c, 0xbf, 0x11, 0xbd, 0xe0, 0x88, 0x0d,
     0x3a, 0x79, 0x52, 0x56, 0xf7, 0xb6, 0xd3, 0x09, 0x16, 0x1b, 0x70, 0xb3, 0x42, 0x60, 0x2f,
     0x1c, 0xa2, 0x9f, 0x72, 0x12, 0x45, 0x47, 0xbb, 0xe1, 0x0b, 0x01, 0x8b, 0x1d, 0xde, 0xec,
     0x0c, 0x4e, 0xe9, 0xcf, 0xcc, 0x95, 0x74, 0xf4, 0xa5, 0x93, 0xc7, 0xdb, 0x4d, 0xfb, 0x35,
     0x65, 0xfe, 0xe7, 0x39, 0xb5, 0xea, 0x96, 0xc3, 0x04, 0x41, 0x44, 0x84, 0xfc, 0x6d, 0x30,
     0xe2, 0xf2, 0x68, 0xb7, 0x89, 0x7d, 0x73, 0x3d, 0xb9, 0x5a, 0x50, 0xa6, 0x3c, 0x61, 0xaa,
     0x2e},
    {0x1a, 0x59, 0x9c, 0xad, 0xc8, 0xe4, 0x11, 0x54, 0xed, 0x37, 0x0f, 0x3a, 0xe6, 0x5f, 0x3c,
     0x4b, 0xb8, 0x15, 0x89, 0xb1, 0xe8, 0xda, 0x69, 0x77, 0x91, 0x56, 0x8b, 0xdb, 0x06, 0x24,
     0xcf, 0x18, 0xf8, 0xb0, 0x87, 0xdf, 0x8c, 0x35, 0xcb, 0x86, 0x53, 0x9d, 0xa4, 0x66, 0x4a,
     0x7a, 0x71, 0x0a, 0x48, 0x38, 0xff, 0xdc, 0x83, 0x20, 0xce, 0x98, 0x32, 0xf6, 0xd7, 0xaf,
     0x70, 0x5e, 0x73, 0x8a, 0x14, 0x72, 0x1e, 0xc1, 0x29, 0x79, 0x07, 0x08, 0xe9, 0x43, 0x46,
     0xd0, 0x2f, 0xde, 0x2a, 0x4f, 0x3d, 0x2c, 0x50, 0xb3, 0x75, 0xfc, 0x0b, 0x64, 0xae, 0x31,
     0x7b, 0x61, 0xa5, 0x30, 0xa0, 0x93, 0xd2, 0xbe, 0xc2, 0x55, 0xba, 0x6c, 0xf3, 0x62, 0x68,
     0xfd, 0xac, 0x3b, 0x95, 0x49, 0x1f, 0x6b, 0xb4, 0x85, 0xf7, 0xa6, 0x03, 0xec, 0x6e, 0x9a,
     0x81, 0x09, 0x0c, 0x6a, 0xee, 0x9e, 0x4e, 0xf0, 0xab, 0x2d, 0x7e, 0xa1, 0xe1, 0xbb, 0xc9,
     0xbc, 0x41, 0xf2, 0xfa, 0x2e, 0x1b, 0xdd, 0x27, 0x34, 0xd3, 0x60, 0x04, 0xb5, 0x01, 0xd6,
     0x40, 0xf9, 0xd5, 0x02, 0x47, 0xd9, 0xd8, 0xe0, 0x8f, 0x2b, 0xfb, 0xb7, 0xc5, 0xeb, 0x57,
     0x16, 0xe5, 0x78, 0x8d, 0xf4, 0x00, 0xcd, 0x82, 0x39, 0xc6, 0x96, 0xbd, 0xbf, 0xe3, 0x36,
     0x45, 0x0e, 0x26, 0x1d, 0x63, 0xe7, 0x84, 0x3e, 0xb6, 0x9b, 0x22, 0xa3, 0xf5, 0x8e, 0x23,
     0x6d, 0xc3, 0x99, 0x7d, 0x90, 0x97, 0x10, 0x25, 0x80, 0xd4, 0x4c, 0xe2, 0x74, 0xcc, 0xb2,
     0x5c, 0x33, 0xc7, 0xea, 0x05, 0x12, 0x3f, 0x51, 0xa8, 0xfe, 0xf1, 0x1c, 0x42, 0xca, 0xd1,
     0x76, 0x28, 0x6f, 0x92, 0xa7, 0x67, 0xa9, 0x19, 0xa2, 0x44, 0x5b, 0xaa, 0xef, 0x58, 0x7f,
     0x21, 0xc0, 0x88, 0x65, 0xb9, 0x5d, 0x4d, 0x0d, 0x5a, 0xc4, 0x13, 0x52, 0x7c, 0x9f, 0x94,
     0x17},
    {0xc7, 0x2b, 0x82, 0x61, 0x5b, 0xd0, 0x96, 0x84, 0xd3, 0x4a, 0x70, 0xa1, 0x9b, 0x59, 0x33,
     0x9f, 0xc0, 0x20, 0x14, 0x53, 0x29, 0x17, 0xc5, 0x0b, 0xc9, 0x7b, 0x97, 0x02, 0x0d, 0x3a,
     0x1e, 0x7c, 0x3f, 0x6b, 0x52, 0xe8, 0x75, 0x3d, 0xf6, 0xe4, 0x0c, 0x8a, 0x4f, 0xc3, 0x5f,
     0x26, 0x65, 0x73, 0x31, 0x23, 0x28, 0x48, 0x74, 0xaa, 0xa7, 0x36, 0x09, 0xb1, 0xe2, 0x91,
     0x04, 0x51, 0x22, 0xfc, 0x08, 0xa6, 0x05, 0xa4, 0xf1, 0x12, 0x1c, 0x19, 0xeb, 0x40, 0x37,
     0xc2, 0xa0, 0x41, 0x1d, 0xd4, 0xdc, 0x07, 0x43, 0x8f, 0x47, 0xaf, 0xd1, 0x2e, 0x98, 0xab,
     0x01, 0xba, 0xf0, 0x66, 0x68, 0xac, 0xf9, 0xe7, 0x69, 0xb6, 0xcb, 0x8d, 0x78, 0x87, 0x15,
     0x03, 0xd5, 0xdf, 0xa3, 0x1a, 0x9d, 0x6a, 0xea, 0x2f, 0x94, 0x4e, 0x9e, 0x42, 0xd7, 0xb8,
     0x38, 0x92, 0xd8, 0xbb, 0xde, 0xdd, 0x9a, 0xbc, 0xb0, 0x4c, 0x79, 0xf4, 0x58, 0x3e, 0xe9,
     0x83, 0x81, 0xff, 0xe3, 0x55, 0xfd, 0x5d, 0xb2, 0xef, 0x9c, 0x6d, 0x54, 0x99, 0x60, 0xda,
     0x3b, 0xec, 0xfa, 0x11, 0xd6, 0xc4, 0x2a, 0xed, 0x4b, 0xae, 0x13, 0xbf, 0xb9, 0x06, 0x8b,
     0xe0, 0x1f, 0x7f, 0x5a, 0xad, 0x90, 0x39, 0x0f, 0xf3, 0xbd, 0x46, 0x6c, 0x2c, 0xf2, 0xf8,
     0xfe, 0xd9, 0xe6, 0x72, 0x0e, 0x89, 0xbe, 0x5e, 0xc6, 0xa8, 0xcf, 0xf5, 0x57, 0x7e, 0x8c,
     0xb7, 0xe1, 0x88, 0x7a, 0xc8, 0x1b, 0x18, 0xdb, 0x6f, 0x35, 0xd2, 0x16, 0x32, 0x64, 0x63,
     0xa5, 0x8e, 0xf7, 0xb4, 0x76, 0x95, 0x86, 0x7d, 0xe5, 0xa9, 0x5c, 0x85, 0x00, 0xc1, 0x93,
     0x4d, 0xfb, 0x30, 0xa2, 0xb5, 0x25, 0x34, 0x10, 0x77, 0x3c, 0x67, 0x71, 0x2d, 0x44, 0x45,
     0x56, 0x0a, 0x50, 0xb3, 0xcd, 0x62, 0x80, 0xce, 0x21, 0x49, 0x24, 0xca, 0xee, 0x27, 0x6e,
     0xcc},
    {0xa5, 0xb0, 0x6d, 0xb2, 0x51, 0x55, 0x1f, 0xbf, 0x3e, 0x8d, 0xdd, 0x19, 0x92, 0xea, 0x1b,
     0xbd, 0x32, 0x65, 0x29, 0xa4, 0x89, 0x67, 0xb1, 0x90, 0x68, 0x00, 0xda, 0x0d, 0xa6, 0x59,
     0x54, 0xf2, 0x10, 0x14, 0x2f, 0x45, 0xe0, 0x3b, 0x23, 0xfa, 0xd7, 0x50, 0xac, 0x93, 0xe6,
     0x43, 0x01, 0x0a, 0x5c, 0x78, 0x70, 0x98, 0x46, 0xa9, 0x7b, 0xf3, 0x95, 0x07, 0x2a, 0xd3,
     0x74, 0xb3, 0x3f, 0xa3, 0x60, 0x82, 0x39, 0x4e, 0x34, 0x48, 0xc0, 0x1c, 0xf6, 0xc2, 0x91,
     0x64, 0x4d, 0x3c, 0xf8, 0x9d, 0x35, 0x9a, 0x94, 0xe3, 0x7a, 0xf0, 0xf9, 0x6e, 0xb9, 0x12,
     0xb8, 0x04, 0x2d, 0x02, 0x28, 0x13, 0x85, 0x72, 0x80, 0x87, 0xdb, 0x2b, 0xf1, 0x4f, 0x26,
     0xa2, 0xe1, 0x49, 0x7e, 0x9c, 0xcc, 0xa7, 0xb6, 0xa0, 0xd0, 0x9b, 0x36, 0x77, 0xad, 0x8b,
     0x6b, 0x4a, 0x03, 0x1d, 0x05, 0x8a, 0x06, 0x4b, 0xaf, 0xe5, 0x31, 0xb5, 0xd4, 0xc6, 0x0c,
     0x66, 0xba, 0x83, 0xfd, 0x09, 0x0f, 0xae, 0x71, 0xb7, 0x6f, 0xdc, 0x41, 0xe8, 0x17, 0x8e,
     0x40, 0x7f, 0x62, 0x30, 0xff, 0xa8, 0x84, 0x25, 0xfb, 0x16, 0xce, 0x37, 0x44, 0xab, 0x99,
     0x1e, 0xeb, 0x18, 0x3a, 0x47, 0xf7, 0x5f, 0x81, 0xcf, 0xed, 0x58, 0x2c, 0x6c, 0xfe, 0x9e,
     0x57, 0x53, 0x97, 0x20, 0xca, 0x79, 0x1a, 0x5a, 0x88, 0xf5, 0x69, 0x9f, 0xe7, 0xd9, 0x0e,
     0xbe, 0x42, 0xdf, 0x56, 0xe4, 0x4c, 0x22, 0xaa, 0x73, 0x0b, 0x15, 0xc5, 0xee, 0xfc, 0xc7,
     0xd6, 0xcb, 0xcd, 0x8c, 0xe2, 0x76, 0x21, 0xe9, 0xd1, 0xec, 0xc8, 0x7d, 0xd8, 0x8f, 0x61,
     0x7c, 0x2e, 0xbc, 0xde, 0xb4, 0x75, 0xd2, 0xc4, 0x63, 0x3d, 0xa1, 0x5e, 0x5d, 0x6a, 0x08,
     0x24, 0xc9, 0x27, 0xbb, 0xef, 0x33, 0x86, 0x5b, 0xd5, 0x38, 0x52, 0x11, 0xf4, 0xc3, 0x96,
     0xc1},
    {0x34, 0x5a, 0xdb, 0x2c, 0x59, 0x57, 0x12, 0x2b, 0x30, 0xc2, 0xa0, 0x92, 0xbf, 0xed, 0xbc,
     0x45, 0xde, 0x27, 0x9b, 0x96, 0xd3, 0xe6, 0xc5, 0xeb, 0xd8, 0x24, 0x4b, 0xa4, 0x21, 0xcc,
     0xa8, 0xd6, 0xce, 0x3c, 0xba, 0xb1, 0x09, 0xe0, 0xd7, 0x32, 0x66, 0x4a, 0x83, 0x1d, 0x19,
     0xca, 0x89, 0x67, 0x0f, 0x42, 0x07, 0x71, 0xe9, 0xbb, 0x44, 0x5e, 0x85, 0x17, 0xc4, 0xae,
     0x9c, 0x3f, 0x6b, 0x78, 0xe7, 0x6d, 0x02, 0xa7, 0xfe, 0x33, 0xe3, 0xd9, 0x0a, 0x7d, 0xea,
     0xf1, 0x18, 0x87, 0x7b, 0x62, 0x03, 0x79, 0x52, 0x23, 0x00, 0x3e, 0x25, 0xb9, 0xdd, 0x16,
     0x68, 0x3b, 0x1f, 0x90, 0xa6, 0x2a, 0xc6, 0x29, 0x91, 0x8a, 0x9d, 0xef, 0x1e, 0x84, 0x76,
     0xee, 0x4f, 0x39, 0xfb, 0x11, 0x1b, 0x0b, 0x93, 0xad, 0x49, 0xb7, 0x05, 0xe1, 0x4d, 0xcb,
     0xe8, 0x38, 0xd0, 0x55, 0xf2, 0xf7, 0x0d, 0x8b, 0x65, 0xcd, 0xfa, 0xd4, 0x9e, 0xc9, 0x81,
     0x4e, 0x14, 0xc8, 0x26, 0xb6, 0xf9, 0xaa, 0xf5, 0x80, 0xf8, 0x6a, 0x98, 0xab, 0x58, 0xf3,
     0xb8, 0x8e, 0xb5, 0x97, 0x43, 0x72, 0xa2, 0xda, 0x64, 0xc1, 0x40, 0x5c, 0x13, 0xb0, 0xe5,
     0xbd, 0x08, 0x9f, 0x1c, 0x7e, 0x8f, 0x06, 0xbe, 0x6e, 0x50, 0x1a, 0x2f, 0x37, 0xa1, 0xfc,
     0x10, 0x2e, 0x70, 0x53, 0x04, 0x20, 0x63, 0x48, 0xe2, 0xfd, 0x6f, 0x7a, 0x75, 0x61, 0xb3,
     0x35, 0x3a, 0xcf, 0x5b, 0x88, 0x82, 0x51, 0xd2, 0x47, 0xa5, 0xa9, 0x74, 0x6c, 0x31, 0x94,
     0x7c, 0x9a, 0xc0, 0xec, 0x15, 0x0e, 0x28, 0x01, 0x2d, 0xc3, 0xf0, 0xb4, 0xe4, 0x8d, 0xdc,
     0xac, 0x3d, 0x5f, 0x86, 0xc7, 0x95, 0x22, 0xf4, 0xb2, 0xa3, 0x54, 0x46, 0xd1, 0x77, 0x8c,
     0x0c, 0xff, 0xaf, 0x56, 0x5d, 0x36, 0x69, 0x7f, 0x99, 0x4c, 0xd5, 0x60, 0x73, 0xdf, 0x41,
     0xf6},
    {0x04, 0xda, 0x79, 0x63, 0x1e, 0xbd, 0xea, 0xe3, 0x0b, 0x65, 0x25, 0x01, 0xcd, 0xa9, 0x92,
     0xed, 0x18, 0x75, 0x57, 0x30, 0x89, 0x03, 0x09, 0x6a, 0xdc, 0xc7, 0x98, 0xa4, 0x50, 0x91,
     0x1f, 0xb1, 0x0c, 0x77, 0x85, 0x66, 0xca, 0x12, 0x1c, 0x67, 0xc2, 0xe0, 0x17, 0x83, 0x59,
     0x9d, 0xd5, 0x22, 0x82, 0x56, 0xa8, 0x9f, 0xc6, 0x60, 0x48, 0xb3, 0x11, 0xfc, 0xa3, 0x28,
     0xfb, 0x06, 0xdd, 0x5d, 0xba, 0x29, 0x7a, 0x4f, 0xe8, 0xfe, 0xe9, 0x10, 0xcb, 0xf3, 0x93,
     0x7b, 0x6c, 0x69, 0x54, 0xe7, 0x44, 0xa2, 0x84, 0x1d, 0x8d, 0xce, 0xff, 0xfa, 0x1a, 0x87,
     0x90, 0x74, 0xa1, 0xf8, 0x14, 0xaa, 0xbc, 0xc0, 0xcf, 0x31, 0xb4, 0xd9, 0xbf, 0xd8, 0x5e,
     0x26, 0x2d, 0xd0, 0xe4, 0x3f, 0x19, 0xd6, 0x8c, 0x2f, 0xab, 0x39, 0x58, 0x72, 0x6e, 0xdf,
     0x3b, 0xe6, 0x3c, 0xb6, 0x62, 0x88, 0xde, 0x40, 0xb2, 0x8f, 0x9b, 0x7c, 0x95, 0x43, 0xd1,
     0x9e, 0xac, 0x9c, 0xd4, 0x23, 0xe1, 0x0e, 0x4b, 0x53, 0x33, 0x46, 0x20, 0x13, 0x34, 0x1b,
     0x97, 0xf7, 0xf1, 0xc3, 0x61, 0x4a, 0x6f, 0x5a, 0x21, 0x7f, 0x70, 0x2e, 0x55, 0x41, 0x05,
     0xc5, 0xd7, 0x76, 0xe5, 0x27, 0x15, 0xec, 0x42, 0x5c, 0x4d, 0x78, 0x35, 0x8b, 0xef, 0xd2,
     0xee, 0xb5, 0xbe, 0xae, 0x02, 0x3a, 0xd3, 0x5f, 0xc4, 0x24, 0xf0, 0xf9, 0x51, 0x4e, 0xeb,
     0x00, 0x0f, 0xfd, 0xaf, 0x3e, 0xc1, 0x9a, 0x52, 0x86, 0x81, 0x80, 0x7e, 0xf6, 0x2b, 0xcc,
     0xb9, 0x7d, 0x68, 0xf2, 0xad, 0x99, 0xa7, 0x07, 0x2c, 0x73, 0x38, 0xb0, 0x6b, 0xb7, 0x8e,
     0x71, 0xa0, 0xf4, 0x3d, 0xa6, 0x0d, 0x37, 0xdb, 0x0a, 0x47, 0x36, 0x16, 0x96, 0x6d, 0x32,
     0x2a, 0x5b, 0xe2, 0x45, 0x94, 0xf5, 0xa5, 0x4c, 0xc8, 0x8a, 0x49, 0x64, 0xbb, 0x08, 0xc9,
     0xb8},
};

static void aic_rotate_right(uint8_t* data, int n_bytes, int n_bits) {
    uint8_t prior = data[n_bytes - 1];
    for(int i = 0; i < n_bytes; i++) {
        uint8_t tmp = data[i];
        data[i] = (data[i] >> n_bits) | ((prior & ((1 << n_bits) - 1)) << (8 - n_bits));
        prior = tmp;
    }
}

static void aic_decrypt_spad_0(const uint8_t* spad, uint8_t* decrypted) {
    for(int i = 0; i < 16; i++) {
        decrypted[i] = aic_s_box[AIC_N_TABLES][spad[i]];
    }

    int count = (decrypted[15] >> 4) + 7;
    int table = decrypted[15] + AIC_ITERATION_ADD * count;

    for(int iter = 0; iter < count; iter++) {
        table -= AIC_ITERATION_ADD;
        aic_rotate_right(decrypted, 15, 5); // 仅前 15 字节循环右移 5 位
        for(int i = 0; i < 15; i++) {
            decrypted[i] = aic_s_box[table % AIC_N_TABLES][decrypted[i]];
        }
    }
}

typedef enum {
    CardPresentNone = 0,
    CardPresentMifare = 0x10,
    CardPresentFelica = 0x20,
} CardPresentType;

struct AimeReader {
    NotificationApp* notifications;
    FuriStreamBuffer* rx_stream;
    FuriThread* worker_thread;
    FuriThread* nfc_thread;
    FuriMutex* state_mutex;
    FuriSemaphore* nfc_done_sem;
    FuriSemaphore* mifare_read_sem;
    CdcCallbacks cdc_callbacks;
    volatile bool running;

    NfcPoller* current_poller;

    // 837-15396 串口协议解析状态机
    AimePacketRequest req;
    AimePacketResponse res;
    uint8_t rx_len;
    uint8_t rx_checksum;
    bool rx_escape;

    // 卡片状态缓存
    volatile CardPresentType card_present;
    bool is_virtual_mifare;
    uint8_t cached_uid[7];
    uint8_t cached_uid_len;
    uint8_t cached_idm[8];
    uint8_t cached_pmm[8];
    uint8_t virtual_ac_bcd[10]; // 解密 S-PAD 0 后得到的 10 字节 BCD Access Code

    // MIFARE 读块同步
    volatile bool mifare_read_req;
    volatile uint8_t mifare_read_block;
    uint8_t mifare_read_out[16];
    volatile bool mifare_read_ok;

    // MIFARE 密钥缓存
    uint8_t key_a[6];
    uint8_t key_b[6];
    bool auth_a_ready;
    bool auth_b_ready;

    // UI 状态
    AimeReaderState state;
    uint8_t last_r;
    uint8_t last_g;
    uint8_t last_b;
};

// Aime Sector 0 template. Only Block 0 UID/BCC are generated per detected card.
// These constants are based on the Aime sample dump supplied for this project.
static const uint8_t aime_sector0_block0_template[16] = {
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x88,
    0x04,
    0x00,
    0xC8,
    0x02,
    0x00,
    0x20,
    0x00,
    0x00,
    0x00,
    0x18,
};

static const uint8_t aime_sector0_block1_template[16] = {
    0x53,
    0x42,
    0x53,
    0x44,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x4F,
    0x83,
    0xE0,
};

static const uint8_t aime_sector0_block3_template[16] = {
    0x57,
    0x43,
    0x43,
    0x46,
    0x76,
    0x32,
    0x70,
    0xF8,
    0x78,
    0x11,
    0x57,
    0x43,
    0x43,
    0x46,
    0x76,
    0x32,
};

#define AIME_SETTINGS_FILE      APP_DATA_PATH("settings.bin")
#define AIME_SETTINGS_SIZE      7U
#define AIME_SETTINGS_VERSION   1U
#define AIME_SETTINGS_CHECK_XOR 0xA5U

static uint8_t aime_settings_checksum(const uint8_t* data) {
    uint8_t checksum = AIME_SETTINGS_CHECK_XOR;
    for(size_t i = 0; i < AIME_SETTINGS_SIZE - 1U; i++) {
        checksum ^= data[i];
    }
    return checksum;
}

static bool aime_settings_resolve_path(Storage* storage, FuriString* path) {
    if(!storage || !path) return false;
    furi_string_set(path, AIME_SETTINGS_FILE);
    storage_common_resolve_path_and_ensure_app_directory(storage, path);
    return true;
}

static void aime_settings_load(AimeReader* instance) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    if(!storage) return;

    File* file = storage_file_alloc(storage);
    FuriString* path = furi_string_alloc();
    uint8_t data[AIME_SETTINGS_SIZE] = {0};
    bool loaded = false;

    if(file && aime_settings_resolve_path(storage, path) &&
       storage_file_open(file, furi_string_get_cstr(path), FSAM_READ, FSOM_OPEN_EXISTING)) {
        loaded = (storage_file_read(file, data, sizeof(data)) == sizeof(data));
        storage_file_close(file);
    }

    if(loaded && data[0] == 'A' && data[1] == 'I' && data[2] == 'M' && data[3] == 'E' &&
       data[4] == AIME_SETTINGS_VERSION && data[6] == aime_settings_checksum(data)) {
        instance->state.high_baudrate = (data[5] & 0x01U) != 0;
        instance->state.aic_as_mifare = (data[5] & 0x02U) != 0;
    }

    if(path) furi_string_free(path);
    if(file) storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
}

static bool aime_settings_save(AimeReader* instance) {
    if(!instance || !instance->state_mutex) return false;

    uint8_t data[AIME_SETTINGS_SIZE] = {'A', 'I', 'M', 'E', AIME_SETTINGS_VERSION, 0, 0};
    furi_mutex_acquire(instance->state_mutex, FuriWaitForever);
    if(instance->state.high_baudrate) data[5] |= 0x01U;
    if(instance->state.aic_as_mifare) data[5] |= 0x02U;
    furi_mutex_release(instance->state_mutex);
    data[6] = aime_settings_checksum(data);

    Storage* storage = furi_record_open(RECORD_STORAGE);
    if(!storage) return false;

    File* file = storage_file_alloc(storage);
    FuriString* path = furi_string_alloc();
    bool saved = false;

    if(file && aime_settings_resolve_path(storage, path) &&
       storage_file_open(file, furi_string_get_cstr(path), FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        saved = (storage_file_write(file, data, sizeof(data)) == sizeof(data));
        if(saved) saved = storage_file_sync(file);
        storage_file_close(file);
    }

    if(path) furi_string_free(path);
    if(file) storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
    return saved;
}

// --- 1. RGB LED 控制 ---
static void aime_set_led(AimeReader* instance, uint8_t r, uint8_t g, uint8_t b, bool force) {
    if(!instance) return;
    if(!force && r == instance->last_r && g == instance->last_g && b == instance->last_b) {
        return;
    }
    instance->last_r = r;
    instance->last_g = g;
    instance->last_b = b;

    if(instance->state_mutex) {
        furi_mutex_acquire(instance->state_mutex, FuriWaitForever);
        instance->state.led_r = r;
        instance->state.led_g = g;
        instance->state.led_b = b;
        furi_mutex_release(instance->state_mutex);
    }

    if(!instance->notifications) return;

    static NotificationMessage msg_r = {.type = NotificationMessageTypeLedRed};
    static NotificationMessage msg_g = {.type = NotificationMessageTypeLedGreen};
    static NotificationMessage msg_b = {.type = NotificationMessageTypeLedBlue};
    static const NotificationSequence seq = {
        &msg_r,
        &msg_g,
        &msg_b,
        &message_do_not_reset,
        NULL,
    };

    msg_r.data.led.value = r;
    msg_g.data.led.value = g;
    msg_b.data.led.value = b;

    notification_message(instance->notifications, &seq);
}

// --- 2. 串口封包发送 ---
static void aime_packet_write(AimeReader* instance) {
    if(instance->res.cmd == 0) return;

    uint8_t tx_buf[260];
    size_t tx_idx = 0;
    uint8_t checksum = 0;
    uint8_t len = 0;

    tx_buf[tx_idx++] = 0xE0;

    while(len <= instance->res.frame_len) {
        uint8_t w;
        if(len == instance->res.frame_len) {
            w = checksum;
        } else {
            w = instance->res.bytes[len];
            checksum += w;
        }

        if(w == 0xE0 || w == 0xD0) {
            tx_buf[tx_idx++] = 0xD0;
            tx_buf[tx_idx++] = (uint8_t)(w - 1);
        } else {
            tx_buf[tx_idx++] = w;
        }
        len++;
    }

    furi_hal_cdc_send(CDC_IF_NUM, tx_buf, tx_idx);
    instance->res.cmd = 0;
}

static void aime_res_init(AimeReader* instance, uint8_t payload_len) {
    instance->res.frame_len = 6 + payload_len;
    instance->res.addr = instance->req.addr;
    instance->res.seq_no = instance->req.seq_no;
    instance->res.cmd = instance->req.cmd;
    instance->res.status = STATUS_OK;
    instance->res.payload_len = payload_len;
}

// --- 3. 后台 NFC 线程 ---
typedef struct {
    AimeReader* app;
    bool read_spad; // true: 允许 Poller 继续读取 Lite-S S-PAD 0
    bool got_card;
    bool got_aic_spad;
    uint8_t idm[8];
    uint8_t pmm[8];
    uint8_t spad0[16];
} PollSyncCtx;

static NfcCommand iso3a_poll_cb(NfcGenericEvent event, void* context) {
    PollSyncCtx* ctx = context;
    if(!ctx || !ctx->app->running) {
        if(ctx) furi_semaphore_release(ctx->app->nfc_done_sem);
        return NfcCommandStop;
    }
    if(event.protocol == NfcProtocolIso14443_3a && event.event_data) {
        const Iso14443_3aPollerEvent* ev = event.event_data;
        if(ev->type == Iso14443_3aPollerEventTypeReady) {
            ctx->got_card = true;
            furi_semaphore_release(ctx->app->nfc_done_sem);
            return NfcCommandStop;
        } else if(ev->type == Iso14443_3aPollerEventTypeError) {
            furi_semaphore_release(ctx->app->nfc_done_sem);
            return NfcCommandStop;
        }
    }
    return NfcCommandContinue;
}

static NfcCommand felica_poll_cb(NfcGenericEvent event, void* context) {
    PollSyncCtx* ctx = context;
    if(!ctx || !ctx->app->running) {
        if(ctx) furi_semaphore_release(ctx->app->nfc_done_sem);
        return NfcCommandStop;
    }

    if(event.protocol == NfcProtocolFelica && event.event_data) {
        const FelicaPollerEvent* ev = event.event_data;

        if(ev->type == FelicaPollerEventTypeRequestAuthContext) {
            const FelicaData* f_data = nfc_poller_get_data(ctx->app->current_poller);
            if(f_data) {
                memcpy(ctx->idm, f_data->idm.data, sizeof(ctx->idm));
                memcpy(ctx->pmm, f_data->pmm.data, sizeof(ctx->pmm));
                ctx->got_card = true;
            }

            const bool is_lite = f_data &&
                                 (f_data->pmm.data[1] == 0xF0 || f_data->pmm.data[1] == 0xF1);
            if(ctx->read_spad && is_lite) {
                // S-PAD 0 is public on the AIC FeliCa Lite/Lite-S cards we handle.
                // The SDK otherwise tries mutual authentication with an unset card key.
                if(ev->data && ev->data->auth_context) {
                    ev->data->auth_context->skip_auth = true;
                    return NfcCommandContinue;
                }
            }

            // Native FeliCa mode (and non-Lite FeliCa) needs only IDm + PMm.
            furi_semaphore_release(ctx->app->nfc_done_sem);
            return NfcCommandStop;
        } else if(
            ev->type == FelicaPollerEventTypeReady ||
            ev->type == FelicaPollerEventTypeIncomplete) {
            const FelicaData* f_data = nfc_poller_get_data(ctx->app->current_poller);
            if(f_data) {
                memcpy(ctx->idm, f_data->idm.data, sizeof(ctx->idm));
                memcpy(ctx->pmm, f_data->pmm.data, sizeof(ctx->pmm));
                ctx->got_card = true;

                const bool is_lite = (f_data->pmm.data[1] == 0xF0 || f_data->pmm.data[1] == 0xF1);
                if(ctx->read_spad && is_lite) {
                    const FelicaBlock* spad0 = &f_data->data.fs.spad[0];
                    // The poller uses Incomplete when unauthenticated Lite blocks were read.
                    // Accept S-PAD 0 when both response status bytes report success.
                    if(spad0->SF1 == 0x00U && spad0->SF2 == 0x00U) {
                        memcpy(ctx->spad0, spad0->data, sizeof(ctx->spad0));
                        ctx->got_aic_spad = true;
                    }
                }
            }
            furi_semaphore_release(ctx->app->nfc_done_sem);
            return NfcCommandStop;
        } else if(ev->type == FelicaPollerEventTypeError) {
            furi_semaphore_release(ctx->app->nfc_done_sem);
            return NfcCommandStop;
        }
    }
    return NfcCommandContinue;
}

static NfcCommand mf_read_poll_cb(NfcGenericEvent event, void* context) {
    PollSyncCtx* ctx = context;
    if(!ctx || !ctx->app->running) {
        if(ctx) furi_semaphore_release(ctx->app->nfc_done_sem);
        return NfcCommandStop;
    }
    AimeReader* instance = ctx->app;
    if(event.protocol == NfcProtocolMfClassic && event.event_data) {
        const MfClassicPollerEvent* mf_event = event.event_data;
        if(mf_event->type == MfClassicPollerEventTypeRequestMode) {
            mf_event->data->poller_mode.mode = MfClassicPollerModeRead;
            return NfcCommandContinue;
        } else if(mf_event->type == MfClassicPollerEventTypeRequestReadSector) {
            uint8_t sector = mf_classic_get_sector_by_block(instance->mifare_read_block);
            bool use_b = instance->auth_b_ready && !instance->auth_a_ready;
            mf_event->data->read_sector_request_data.sector_num = sector;
            memcpy(
                mf_event->data->read_sector_request_data.key.data,
                use_b ? instance->key_b : instance->key_a,
                6);
            mf_event->data->read_sector_request_data.key_type = use_b ? MfClassicKeyTypeB :
                                                                        MfClassicKeyTypeA;
            mf_event->data->read_sector_request_data.key_provided = true;
            return NfcCommandContinue;
        } else if(mf_event->type == MfClassicPollerEventTypeSuccess) {
            ctx->got_card = true;
            furi_semaphore_release(instance->nfc_done_sem);
            return NfcCommandStop;
        } else if(mf_event->type == MfClassicPollerEventTypeFail) {
            furi_semaphore_release(instance->nfc_done_sem);
            return NfcCommandStop;
        }
    }
    return NfcCommandContinue;
}

static int32_t aime_nfc_thread(void* context) {
    AimeReader* instance = context;
    bool scan_felica_turn = false;
    uint8_t miss_count = 0;

    while(instance->running) {
        // 1. 物理 MIFARE 读块请求
        if(instance->mifare_read_req) {
            PollSyncCtx ctx = {.app = instance, .got_card = false};
            while(furi_semaphore_acquire(instance->nfc_done_sem, 0) == FuriStatusOk) {
            }

            Nfc* nfc = nfc_alloc();
            if(nfc) {
                NfcPoller* poller = nfc_poller_alloc(nfc, NfcProtocolMfClassic);
                if(poller) {
                    nfc_poller_start(poller, mf_read_poll_cb, &ctx);
                    furi_semaphore_acquire(instance->nfc_done_sem, 800);
                    nfc_poller_stop(poller);

                    const MfClassicData* data = nfc_poller_get_data(poller);
                    if(data && mf_classic_is_block_read(data, instance->mifare_read_block)) {
                        memcpy(
                            instance->mifare_read_out,
                            data->block[instance->mifare_read_block].data,
                            16);
                        instance->mifare_read_ok = true;
                    }
                    nfc_poller_free(poller);
                }
                nfc_free(nfc);
            }
            instance->mifare_read_req = false;
            furi_semaphore_release(instance->mifare_read_sem);
            furi_delay_ms(35);
            continue;
        }

        // 2. 主机 Polling 开关检查
        furi_mutex_acquire(instance->state_mutex, FuriWaitForever);
        bool polling = instance->state.is_polling;
        bool aic_emulate = instance->state.aic_as_mifare;
        furi_mutex_release(instance->state_mutex);

        if(!polling) {
            instance->card_present = CardPresentNone;
            instance->is_virtual_mifare = false;
            furi_delay_ms(40);
            continue;
        }

        PollSyncCtx ctx = {
            .app = instance,
            .read_spad = aic_emulate,
            .got_card = false,
            .got_aic_spad = false,
        };
        while(furi_semaphore_acquire(instance->nfc_done_sem, 0) == FuriStatusOk) {
        }

        if(!scan_felica_turn) {
            // --- 周期 A: ISO14443-3A (物理 MIFARE Aime / Banapassport) ---
            Nfc* nfc = nfc_alloc();
            if(nfc) {
                NfcPoller* poller = nfc_poller_alloc(nfc, NfcProtocolIso14443_3a);
                if(poller) {
                    nfc_poller_start(poller, iso3a_poll_cb, &ctx);
                    furi_semaphore_acquire(instance->nfc_done_sem, 55);
                    nfc_poller_stop(poller);

                    if(ctx.got_card) {
                        const Iso14443_3aData* iso_data = nfc_poller_get_data(poller);
                        if(iso_data && iso_data->uid_len > 0 && iso_data->uid_len <= 7) {
                            furi_mutex_acquire(instance->state_mutex, FuriWaitForever);
                            memcpy(instance->cached_uid, iso_data->uid, iso_data->uid_len);
                            instance->cached_uid_len = iso_data->uid_len;
                            instance->card_present = CardPresentMifare;
                            instance->is_virtual_mifare = false;
                            snprintf(
                                instance->state.card_type,
                                sizeof(instance->state.card_type),
                                "MIFARE Classic");
                            snprintf(
                                instance->state.card_id,
                                sizeof(instance->state.card_id),
                                "UID: %02X %02X %02X %02X",
                                iso_data->uid[0],
                                iso_data->uid[1],
                                iso_data->uid[2],
                                iso_data->uid[3]);
                            furi_mutex_release(instance->state_mutex);
                            miss_count = 0;
                        }
                    }
                    nfc_poller_free(poller);
                }
                nfc_free(nfc);
            }
        } else {
            // --- 周期 B: FeliCa (Amusement IC / 手机) ---
            Nfc* nfc = nfc_alloc();
            if(nfc) {
                NfcPoller* poller = nfc_poller_alloc(nfc, NfcProtocolFelica);
                if(poller) {
                    instance->current_poller = poller;
                    nfc_poller_start(poller, felica_poll_cb, &ctx);
                    // Lite/Lite-S poller reads the Lite block sequence before reporting
                    // Incomplete; give it enough time to finish that sequence.
                    furi_semaphore_acquire(instance->nfc_done_sem, aic_emulate ? 1800 : 200);
                    nfc_poller_stop(poller);
                    furi_delay_ms(5);
                    nfc_poller_free(poller);
                    instance->current_poller = NULL;

                    if(ctx.got_card) {
                        bool spad_valid = aic_emulate && ctx.got_aic_spad;
                        uint8_t decrypted[16] = {0};

                        if(spad_valid) {
                            // 使用官方 aic.c S-PAD 0 算法解密；当前阶段不额外做 BCD 白名单校验。
                            aic_decrypt_spad_0(ctx.spad0, decrypted);
                        }

                        furi_mutex_acquire(instance->state_mutex, FuriWaitForever);
                        memcpy(instance->cached_idm, ctx.idm, 8);
                        memcpy(instance->cached_pmm, ctx.pmm, 8);

                        if(spad_valid) {
                            // 成功解出 S-PAD 0 Access Code -> 伪装为 MIFARE Classic 回传
                            instance->card_present = CardPresentMifare;
                            instance->is_virtual_mifare = true;
                            instance->cached_uid_len = 4;
                            memcpy(instance->cached_uid, &ctx.idm[4], 4);

                            memcpy(instance->virtual_ac_bcd, &decrypted[6], 10);

                            snprintf(
                                instance->state.card_type,
                                sizeof(instance->state.card_type),
                                "AIC -> MIFARE Emu");
                            snprintf(
                                instance->state.card_id,
                                sizeof(instance->state.card_id),
                                "IDm:%02X%02X%02X%02X%02X%02X%02X%02X",
                                ctx.idm[0],
                                ctx.idm[1],
                                ctx.idm[2],
                                ctx.idm[3],
                                ctx.idm[4],
                                ctx.idm[5],
                                ctx.idm[6],
                                ctx.idm[7]);
                            snprintf(
                                instance->state.access_code,
                                sizeof(instance->state.access_code),
                                "%02X%02X %02X%02X %02X%02X %02X%02X %02X%02X",
                                decrypted[6],
                                decrypted[7],
                                decrypted[8],
                                decrypted[9],
                                decrypted[10],
                                decrypted[11],
                                decrypted[12],
                                decrypted[13],
                                decrypted[14],
                                decrypted[15]);
                        } else {
                            // 未开启转换或非 AIC 卡（如手机交通卡）：原生 FeliCa 透传
                            instance->card_present = CardPresentFelica;
                            instance->is_virtual_mifare = false;
                            snprintf(
                                instance->state.card_type,
                                sizeof(instance->state.card_type),
                                "FeliCa (Native)");
                            snprintf(
                                instance->state.card_id,
                                sizeof(instance->state.card_id),
                                "IDm:%02X%02X%02X%02X%02X%02X%02X%02X",
                                ctx.idm[0],
                                ctx.idm[1],
                                ctx.idm[2],
                                ctx.idm[3],
                                ctx.idm[4],
                                ctx.idm[5],
                                ctx.idm[6],
                                ctx.idm[7]);
                            snprintf(
                                instance->state.access_code,
                                sizeof(instance->state.access_code),
                                "PMm:%02X%02X%02X%02X%02X%02X%02X%02X",
                                ctx.pmm[0],
                                ctx.pmm[1],
                                ctx.pmm[2],
                                ctx.pmm[3],
                                ctx.pmm[4],
                                ctx.pmm[5],
                                ctx.pmm[6],
                                ctx.pmm[7]);
                        }
                        furi_mutex_release(instance->state_mutex);
                        miss_count = 0;
                    }
                }
                nfc_free(nfc);
            }
        }

        if(!ctx.got_card) {
            if(++miss_count >= 3) {
                instance->card_present = CardPresentNone;
                instance->is_virtual_mifare = false;
            }
            scan_felica_turn = !scan_felica_turn;
        }

        furi_delay_ms(35);
    }
    return 0;
}

// --- 4. 串口指令响应层 ---
static void aime_handle_card_detect(AimeReader* instance) {
    furi_mutex_acquire(instance->state_mutex, FuriWaitForever);
    CardPresentType type = instance->card_present;

    if(type == CardPresentMifare) {
        aime_res_init(instance, instance->cached_uid_len + 3);
        instance->res.count = 1;
        instance->res.type = 0x10;
        instance->res.id_len = instance->cached_uid_len;
        memcpy(instance->res.mifare_uid, instance->cached_uid, instance->cached_uid_len);
    } else if(type == CardPresentFelica) {
        aime_res_init(instance, 0x13);
        instance->res.count = 1;
        instance->res.type = 0x20;
        instance->res.id_len = 0x10;
        memcpy(instance->res.IDm, instance->cached_idm, 8);
        memcpy(instance->res.PMm, instance->cached_pmm, 8);
    } else {
        aime_res_init(instance, 1);
        instance->res.count = 0;
    }
    furi_mutex_release(instance->state_mutex);
}

static void aime_handle_mifare_read(AimeReader* instance) {
    furi_mutex_acquire(instance->state_mutex, FuriWaitForever);
    bool is_virtual = instance->is_virtual_mifare && (instance->card_present == CardPresentMifare);
    uint8_t block_no = instance->req.block_no;
    uint8_t uid[4];
    uint8_t ac_bcd[10];
    memcpy(uid, instance->cached_uid, 4);
    memcpy(ac_bcd, instance->virtual_ac_bcd, 10);
    furi_mutex_release(instance->state_mutex);

    if(is_virtual) {
        aime_res_init(instance, 0x10);
        memset(instance->res.block, 0x00, 16);

        if(block_no == 0) {
            memcpy(instance->res.block, aime_sector0_block0_template, 16);
            memcpy(instance->res.block, uid, 4);
            instance->res.block[4] = uid[0] ^ uid[1] ^ uid[2] ^ uid[3];
        } else if(block_no == 1) {
            memcpy(instance->res.block, aime_sector0_block1_template, 16);
        } else if(block_no == 2) {
            // Aime Block 2 [6..15] 保存 10 字节 Access Code。
            memcpy(&instance->res.block[6], ac_bcd, 10);
        } else if(block_no == 3) {
            // Sector Trailer 模板来自 Aime 样本；认证密钥仍由主机的 KEY_SET 命令管理。
            memcpy(instance->res.block, aime_sector0_block3_template, 16);
        }
        return;
    }

    // 物理 MIFARE 卡片走后台 NFC 线程读取
    while(furi_semaphore_acquire(instance->mifare_read_sem, 0) == FuriStatusOk) {
    }
    instance->mifare_read_block = block_no;
    instance->mifare_read_ok = false;
    instance->mifare_read_req = true;
    // Wake the NFC worker so it can stop the current scan and service this read.
    furi_semaphore_release(instance->nfc_done_sem);
    furi_semaphore_acquire(instance->mifare_read_sem, 1000);

    if(instance->mifare_read_ok) {
        aime_res_init(instance, 0x10);
        memcpy(instance->res.block, instance->mifare_read_out, 16);

        if(instance->mifare_read_block == 2) {
            furi_mutex_acquire(instance->state_mutex, FuriWaitForever);
            snprintf(
                instance->state.access_code,
                sizeof(instance->state.access_code),
                "%02X%02X %02X%02X %02X%02X %02X%02X %02X%02X",
                instance->mifare_read_out[6],
                instance->mifare_read_out[7],
                instance->mifare_read_out[8],
                instance->mifare_read_out[9],
                instance->mifare_read_out[10],
                instance->mifare_read_out[11],
                instance->mifare_read_out[12],
                instance->mifare_read_out[13],
                instance->mifare_read_out[14],
                instance->mifare_read_out[15]);
            furi_mutex_release(instance->state_mutex);
        }
    } else {
        aime_res_init(instance, 0);
        instance->res.status = STATUS_CARD_ERROR;
    }
}

// --- 5. SEGA 837-15396 命令分发 ---
static void aime_dispatch_command(AimeReader* instance, uint8_t cmd_status) {
    furi_mutex_acquire(instance->state_mutex, FuriWaitForever);
    instance->state.rx_packets++;
    bool is_high = instance->state.high_baudrate;
    furi_mutex_release(instance->state_mutex);

    switch(cmd_status) {
    case CMD_TO_NORMAL_MODE:
        aime_res_init(instance, 0);
        instance->res.status = STATUS_INVALID_COMMAND;
        break;

    case CMD_GET_FW_VERSION:
        if(is_high) {
            aime_res_init(instance, AIME_HIGH_FW_LEN);
            memcpy(instance->res.version, AIME_HIGH_FW_VERSION, AIME_HIGH_FW_LEN);
        } else {
            aime_res_init(instance, AIME_LOW_FW_LEN);
            memcpy(instance->res.version, AIME_LOW_FW_VERSION, AIME_LOW_FW_LEN);
        }
        break;

    case CMD_GET_HW_VERSION:
        if(is_high) {
            aime_res_init(instance, AIME_HIGH_HW_LEN);
            memcpy(instance->res.version, AIME_HIGH_HW_VERSION, AIME_HIGH_HW_LEN);
        } else {
            aime_res_init(instance, AIME_LOW_HW_LEN);
            memcpy(instance->res.version, AIME_LOW_HW_VERSION, AIME_LOW_HW_LEN);
        }
        break;

    case CMD_START_POLLING:
        aime_res_init(instance, 0);
        furi_mutex_acquire(instance->state_mutex, FuriWaitForever);
        instance->state.is_polling = true;
        furi_mutex_release(instance->state_mutex);
        break;

    case CMD_STOP_POLLING:
        aime_res_init(instance, 0);
        furi_mutex_acquire(instance->state_mutex, FuriWaitForever);
        instance->state.is_polling = false;
        instance->card_present = CardPresentNone;
        instance->is_virtual_mifare = false;
        furi_mutex_release(instance->state_mutex);
        break;

    case CMD_CARD_DETECT:
        aime_handle_card_detect(instance);
        break;

    case CMD_MIFARE_KEY_SET_A:
        memcpy(instance->key_a, instance->req.key, 6);
        aime_res_init(instance, 0);
        break;

    case CMD_MIFARE_KEY_SET_B:
        memcpy(instance->key_b, instance->req.key, 6);
        aime_res_init(instance, 0);
        break;

    case CMD_MIFARE_AUTHORIZE_A:
        instance->auth_a_ready = true;
        instance->auth_b_ready = false;
        aime_res_init(instance, 0);
        break;

    case CMD_MIFARE_AUTHORIZE_B:
        instance->auth_b_ready = true;
        instance->auth_a_ready = false;
        aime_res_init(instance, 0);
        break;

    case CMD_MIFARE_READ:
        aime_handle_mifare_read(instance);
        break;

    case CMD_EXT_BOARD_LED_RGB:
        aime_set_led(
            instance,
            instance->req.color_payload[0],
            instance->req.color_payload[1],
            instance->req.color_payload[2],
            false);
        return;

    case CMD_EXT_BOARD_INFO:
        if(is_high) {
            aime_res_init(instance, AIME_HIGH_LED_LEN);
            memcpy(instance->res.version, AIME_HIGH_LED_INFO, AIME_HIGH_LED_LEN);
        } else {
            aime_res_init(instance, AIME_LOW_LED_LEN);
            memcpy(instance->res.version, AIME_LOW_LED_INFO, AIME_LOW_LED_LEN);
        }
        break;

    case CMD_EXT_BOARD_LED_RGB_UNKNOWN:
        return;

    case CMD_CARD_SELECT:
    case CMD_CARD_HALT:
    case CMD_EXT_TO_NORMAL_MODE:
    case CMD_TO_UPDATER_MODE:
    case CMD_SEND_BINDATA_INIT:
        aime_res_init(instance, 0);
        break;

    case CMD_SEND_BINDATA_EXEC:
        aime_res_init(instance, 0);
        instance->res.status = STATUS_FIRM_UPDATE_SUCCESS;
        break;

    case CMD_SEND_HEX_DATA:
        aime_res_init(instance, 0);
        instance->res.status = is_high ? STATUS_COMP_DUMMY_3RD : STATUS_OK;
        break;

    case STATUS_SUM_ERROR:
        aime_res_init(instance, 0);
        instance->res.status = STATUS_SUM_ERROR;
        break;

    default:
        aime_res_init(instance, 0);
        instance->res.status = STATUS_INVALID_COMMAND;
        break;
    }

    aime_packet_write(instance);
}

// --- 6. 串口逐字节解包 ---
static void aime_process_byte(AimeReader* instance, uint8_t r) {
    if(r == 0xE0) {
        instance->req.frame_len = 0xFF;
        instance->rx_escape = false;
        return;
    }
    if(instance->req.frame_len == 0xFF) {
        instance->req.frame_len = r;
        instance->rx_len = 0;
        instance->rx_checksum = r;
        return;
    }
    if(r == 0xD0) {
        instance->rx_escape = true;
        return;
    }
    if(instance->rx_escape) {
        r++;
        instance->rx_escape = false;
    }

    if((size_t)(instance->rx_len + 1) < sizeof(instance->req.bytes)) {
        instance->req.bytes[++instance->rx_len] = r;
    }

    if(instance->rx_len == instance->req.frame_len) {
        uint8_t status;
        if(instance->req.cmd == CMD_SEND_BINDATA_EXEC) {
            status = instance->req.cmd;
        } else {
            status = (instance->rx_checksum == r) ? instance->req.cmd : STATUS_SUM_ERROR;
        }
        aime_dispatch_command(instance, status);
        return;
    }

    instance->rx_checksum += r;
}

// --- 7. USB CDC 回调与线程管理 ---
static void cdc_rx_callback(void* context) {
    AimeReader* instance = context;
    if(!instance || !instance->rx_stream) return;
    instance->state.usb_connected = true;
    uint8_t buf[64];
    int32_t len = furi_hal_cdc_receive(CDC_IF_NUM, buf, sizeof(buf));
    if(len > 0) {
        furi_stream_buffer_send(instance->rx_stream, buf, len, 0);
    }
}

static void cdc_tx_callback(void* context) {
    UNUSED(context);
}

static void cdc_state_callback(void* context, CdcState state) {
    AimeReader* instance = context;
    if(!instance) return;
    instance->state.usb_connected = (state == CdcStateConnected);
}

static void cdc_ctrl_line_callback(void* context, uint8_t state) {
    UNUSED(context);
    UNUSED(state);
}

static void cdc_config_callback(void* context, struct usb_cdc_line_coding* config) {
    UNUSED(context);
    UNUSED(config);
}

static int32_t aime_worker_thread(void* context) {
    AimeReader* instance = context;
    uint8_t byte;

    while(instance->running) {
        if(furi_stream_buffer_receive(instance->rx_stream, &byte, 1, 50) == 1) {
            aime_process_byte(instance, byte);
        }
    }
    return 0;
}

AimeReader* aime_reader_alloc(void) {
    AimeReader* instance = malloc(sizeof(AimeReader));
    if(!instance) return NULL;
    memset(instance, 0, sizeof(AimeReader));

    instance->notifications = furi_record_open(RECORD_NOTIFICATION);
    instance->rx_stream = furi_stream_buffer_alloc(512, 1);
    instance->state_mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    instance->nfc_done_sem = furi_semaphore_alloc(1, 0);
    instance->mifare_read_sem = furi_semaphore_alloc(1, 0);

    // Defaults are used only when no valid settings file exists.
    instance->state.high_baudrate = true;
    instance->state.aic_as_mifare = true;
    aime_settings_load(instance);
    instance->state.usb_connected = false;
    snprintf(instance->state.card_type, sizeof(instance->state.card_type), "Waiting for card...");
    snprintf(instance->state.card_id, sizeof(instance->state.card_id), "Tap Aime / AIC / Phone");
    instance->state.access_code[0] = '\0';

    instance->running = true;
    instance->worker_thread =
        furi_thread_alloc_ex("AimeWorker", 4096, aime_worker_thread, instance);
    instance->nfc_thread = furi_thread_alloc_ex("AimeNfc", 8192, aime_nfc_thread, instance);
    furi_thread_start(instance->worker_thread);
    furi_thread_start(instance->nfc_thread);

    instance->cdc_callbacks.rx_ep_callback = cdc_rx_callback;
    instance->cdc_callbacks.tx_ep_callback = cdc_tx_callback;
    instance->cdc_callbacks.state_callback = cdc_state_callback;
    instance->cdc_callbacks.ctrl_line_callback = cdc_ctrl_line_callback;
    instance->cdc_callbacks.config_callback = cdc_config_callback;

    CliVcp* cli_vcp = furi_record_open(RECORD_CLI_VCP);
    cli_vcp_disable(cli_vcp);
    furi_record_close(RECORD_CLI_VCP);

    furi_hal_usb_unlock();
    furi_hal_usb_set_config(&usb_cdc_single, NULL);
    furi_delay_ms(50);

    furi_stream_buffer_reset(instance->rx_stream);
    furi_hal_cdc_set_callbacks(CDC_IF_NUM, &instance->cdc_callbacks, instance);

    aime_set_led(instance, 0x00, 0x00, 0xFF, true);

    return instance;
}

void aime_reader_free(AimeReader* instance) {
    if(!instance) return;

    furi_hal_cdc_set_callbacks(CDC_IF_NUM, NULL, NULL);

    instance->running = false;
    furi_semaphore_release(instance->nfc_done_sem);
    furi_semaphore_release(instance->mifare_read_sem);

    furi_thread_join(instance->worker_thread);
    furi_thread_free(instance->worker_thread);

    furi_thread_join(instance->nfc_thread);
    furi_thread_free(instance->nfc_thread);

    aime_set_led(instance, 0x00, 0x00, 0x00, true);
    CliVcp* cli_vcp = furi_record_open(RECORD_CLI_VCP);
    cli_vcp_enable(cli_vcp);
    furi_record_close(RECORD_CLI_VCP);

    furi_record_close(RECORD_NOTIFICATION);
    furi_stream_buffer_free(instance->rx_stream);
    furi_mutex_free(instance->state_mutex);
    furi_semaphore_free(instance->nfc_done_sem);
    furi_semaphore_free(instance->mifare_read_sem);
    free(instance);
}

void aime_reader_get_state(AimeReader* instance, AimeReaderState* out_state) {
    if(!instance || !out_state) return;
    furi_mutex_acquire(instance->state_mutex, FuriWaitForever);
    memcpy(out_state, &instance->state, sizeof(AimeReaderState));
    furi_mutex_release(instance->state_mutex);
}

void aime_reader_set_baudrate(AimeReader* instance, bool high_baudrate) {
    if(!instance) return;
    furi_mutex_acquire(instance->state_mutex, FuriWaitForever);
    instance->state.high_baudrate = high_baudrate;
    furi_mutex_release(instance->state_mutex);

    if(high_baudrate) {
        aime_set_led(instance, 0x00, 0x00, 0xFF, true);
    } else {
        aime_set_led(instance, 0x00, 0xFF, 0x00, true);
    }
    if(!aime_settings_save(instance)) {
        FURI_LOG_E("AimeReader", "Failed to save baudrate setting");
    }
}

void aime_reader_set_aic_as_mifare(AimeReader* instance, bool enable) {
    if(!instance) return;
    furi_mutex_acquire(instance->state_mutex, FuriWaitForever);
    instance->state.aic_as_mifare = enable;
    instance->card_present = CardPresentNone;
    instance->is_virtual_mifare = false;
    furi_mutex_release(instance->state_mutex);
    if(!aime_settings_save(instance)) {
        FURI_LOG_E("AimeReader", "Failed to save AIC mode setting");
    }
}
