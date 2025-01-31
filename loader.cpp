// SimpleLoader.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>

// insert shellcode here
unsigned char text_section[] = {
	0x56, 0x48, 0x8B, 0xF4, 0x48, 0x83, 0xE4, 0xF0, 0x48, 0x83, 0xEC, 0x20, 0xE8, 0x05, 0x00, 0x00,
	0x00, 0x48, 0x8B, 0xE6, 0x5E, 0xC3, 0x48, 0x81, 0xEC, 0xF8, 0x00, 0x00, 0x00, 0xB8, 0x6B, 0x00,
	0x00, 0x00, 0x66, 0x89, 0x44, 0x24, 0x70, 0xB8, 0x65, 0x00, 0x00, 0x00, 0x66, 0x89, 0x44, 0x24,
	0x72, 0xB8, 0x72, 0x00, 0x00, 0x00, 0x66, 0x89, 0x44, 0x24, 0x74, 0xB8, 0x6E, 0x00, 0x00, 0x00,
	0x66, 0x89, 0x44, 0x24, 0x76, 0xB8, 0x65, 0x00, 0x00, 0x00, 0x66, 0x89, 0x44, 0x24, 0x78, 0xB8,
	0x6C, 0x00, 0x00, 0x00, 0x66, 0x89, 0x44, 0x24, 0x7A, 0xB8, 0x33, 0x00, 0x00, 0x00, 0x66, 0x89,
	0x44, 0x24, 0x7C, 0xB8, 0x32, 0x00, 0x00, 0x00, 0x66, 0x89, 0x44, 0x24, 0x7E, 0xB8, 0x2E, 0x00,
	0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00, 0xB8, 0x64, 0x00, 0x00, 0x00, 0x66,
	0x89, 0x84, 0x24, 0x82, 0x00, 0x00, 0x00, 0xB8, 0x6C, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24,
	0x84, 0x00, 0x00, 0x00, 0xB8, 0x6C, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x86, 0x00, 0x00,
	0x00, 0x33, 0xC0, 0x66, 0x89, 0x84, 0x24, 0x88, 0x00, 0x00, 0x00, 0xC6, 0x44, 0x24, 0x40, 0x4C,
	0xC6, 0x44, 0x24, 0x41, 0x6F, 0xC6, 0x44, 0x24, 0x42, 0x61, 0xC6, 0x44, 0x24, 0x43, 0x64, 0xC6,
	0x44, 0x24, 0x44, 0x4C, 0xC6, 0x44, 0x24, 0x45, 0x69, 0xC6, 0x44, 0x24, 0x46, 0x62, 0xC6, 0x44,
	0x24, 0x47, 0x72, 0xC6, 0x44, 0x24, 0x48, 0x61, 0xC6, 0x44, 0x24, 0x49, 0x72, 0xC6, 0x44, 0x24,
	0x4A, 0x79, 0xC6, 0x44, 0x24, 0x4B, 0x41, 0xC6, 0x44, 0x24, 0x4C, 0x00, 0xC6, 0x44, 0x24, 0x50,
	0x47, 0xC6, 0x44, 0x24, 0x51, 0x65, 0xC6, 0x44, 0x24, 0x52, 0x74, 0xC6, 0x44, 0x24, 0x53, 0x50,
	0xC6, 0x44, 0x24, 0x54, 0x72, 0xC6, 0x44, 0x24, 0x55, 0x6F, 0xC6, 0x44, 0x24, 0x56, 0x63, 0xC6,
	0x44, 0x24, 0x57, 0x41, 0xC6, 0x44, 0x24, 0x58, 0x64, 0xC6, 0x44, 0x24, 0x59, 0x64, 0xC6, 0x44,
	0x24, 0x5A, 0x72, 0xC6, 0x44, 0x24, 0x5B, 0x65, 0xC6, 0x44, 0x24, 0x5C, 0x73, 0xC6, 0x44, 0x24,
	0x5D, 0x73, 0xC6, 0x44, 0x24, 0x5E, 0x00, 0xC6, 0x44, 0x24, 0x20, 0x75, 0xC6, 0x44, 0x24, 0x21,
	0x73, 0xC6, 0x44, 0x24, 0x22, 0x65, 0xC6, 0x44, 0x24, 0x23, 0x72, 0xC6, 0x44, 0x24, 0x24, 0x33,
	0xC6, 0x44, 0x24, 0x25, 0x32, 0xC6, 0x44, 0x24, 0x26, 0x2E, 0xC6, 0x44, 0x24, 0x27, 0x64, 0xC6,
	0x44, 0x24, 0x28, 0x6C, 0xC6, 0x44, 0x24, 0x29, 0x6C, 0xC6, 0x44, 0x24, 0x2A, 0x00, 0xC6, 0x44,
	0x24, 0x30, 0x4D, 0xC6, 0x44, 0x24, 0x31, 0x65, 0xC6, 0x44, 0x24, 0x32, 0x73, 0xC6, 0x44, 0x24,
	0x33, 0x73, 0xC6, 0x44, 0x24, 0x34, 0x61, 0xC6, 0x44, 0x24, 0x35, 0x67, 0xC6, 0x44, 0x24, 0x36,
	0x65, 0xC6, 0x44, 0x24, 0x37, 0x42, 0xC6, 0x44, 0x24, 0x38, 0x6F, 0xC6, 0x44, 0x24, 0x39, 0x78,
	0xC6, 0x44, 0x24, 0x3A, 0x57, 0xC6, 0x44, 0x24, 0x3B, 0x00, 0xB8, 0x48, 0x00, 0x00, 0x00, 0x66,
	0x89, 0x84, 0x24, 0x90, 0x00, 0x00, 0x00, 0xB8, 0x65, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24,
	0x92, 0x00, 0x00, 0x00, 0xB8, 0x6C, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x94, 0x00, 0x00,
	0x00, 0xB8, 0x6C, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x96, 0x00, 0x00, 0x00, 0xB8, 0x6F,
	0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x98, 0x00, 0x00, 0x00, 0xB8, 0x20, 0x00, 0x00, 0x00,
	0x66, 0x89, 0x84, 0x24, 0x9A, 0x00, 0x00, 0x00, 0xB8, 0x57, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84,
	0x24, 0x9C, 0x00, 0x00, 0x00, 0xB8, 0x6F, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0x9E, 0x00,
	0x00, 0x00, 0xB8, 0x72, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xA0, 0x00, 0x00, 0x00, 0xB8,
	0x6C, 0x00, 0x00, 0x00, 0x66, 0x89, 0x84, 0x24, 0xA2, 0x00, 0x00, 0x00, 0xB8, 0x64, 0x00, 0x00,
	0x00, 0x66, 0x89, 0x84, 0x24, 0xA4, 0x00, 0x00, 0x00, 0xB8, 0x21, 0x00, 0x00, 0x00, 0x66, 0x89,
	0x84, 0x24, 0xA6, 0x00, 0x00, 0x00, 0x33, 0xC0, 0x66, 0x89, 0x84, 0x24, 0xA8, 0x00, 0x00, 0x00,
	0xB8, 0x44, 0x00, 0x00, 0x00, 0x66, 0x89, 0x44, 0x24, 0x60, 0xB8, 0x65, 0x00, 0x00, 0x00, 0x66,
	0x89, 0x44, 0x24, 0x62, 0xB8, 0x6D, 0x00, 0x00, 0x00, 0x66, 0x89, 0x44, 0x24, 0x64, 0xB8, 0x6F,
	0x00, 0x00, 0x00, 0x66, 0x89, 0x44, 0x24, 0x66, 0xB8, 0x21, 0x00, 0x00, 0x00, 0x66, 0x89, 0x44,
	0x24, 0x68, 0x33, 0xC0, 0x66, 0x89, 0x44, 0x24, 0x6A, 0x48, 0x8D, 0x4C, 0x24, 0x70, 0xE8, 0x37,
	0x03, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 0xB0, 0x00, 0x00, 0x00, 0x48, 0x83, 0xBC, 0x24, 0xB0,
	0x00, 0x00, 0x00, 0x00, 0x75, 0x0A, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xE9, 0xD8, 0x00, 0x00, 0x00,
	0x48, 0x8D, 0x54, 0x24, 0x40, 0x48, 0x8B, 0x8C, 0x24, 0xB0, 0x00, 0x00, 0x00, 0xE8, 0xCE, 0x00,
	0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 0xB8, 0x00, 0x00, 0x00, 0x48, 0x83, 0xBC, 0x24, 0xB8, 0x00,
	0x00, 0x00, 0x00, 0x75, 0x0A, 0xB8, 0x02, 0x00, 0x00, 0x00, 0xE9, 0xA9, 0x00, 0x00, 0x00, 0x48,
	0x8D, 0x54, 0x24, 0x50, 0x48, 0x8B, 0x8C, 0x24, 0xB0, 0x00, 0x00, 0x00, 0xE8, 0x9F, 0x00, 0x00,
	0x00, 0x48, 0x89, 0x84, 0x24, 0xC0, 0x00, 0x00, 0x00, 0x48, 0x83, 0xBC, 0x24, 0xC0, 0x00, 0x00,
	0x00, 0x00, 0x75, 0x07, 0xB8, 0x03, 0x00, 0x00, 0x00, 0xEB, 0x7D, 0x48, 0x8B, 0x84, 0x24, 0xB8,
	0x00, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 0xD0, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x84, 0x24, 0xC0,
	0x00, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 0xE0, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x4C, 0x24, 0x20,
	0xFF, 0x94, 0x24, 0xD0, 0x00, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 0xD8, 0x00, 0x00, 0x00, 0x48,
	0x8D, 0x54, 0x24, 0x30, 0x48, 0x8B, 0x8C, 0x24, 0xD8, 0x00, 0x00, 0x00, 0xFF, 0x94, 0x24, 0xE0,
	0x00, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 0xC8, 0x00, 0x00, 0x00, 0x48, 0x83, 0xBC, 0x24, 0xC8,
	0x00, 0x00, 0x00, 0x00, 0x75, 0x07, 0xB8, 0x04, 0x00, 0x00, 0x00, 0xEB, 0x1B, 0x45, 0x33, 0xC9,
	0x4C, 0x8D, 0x44, 0x24, 0x60, 0x48, 0x8D, 0x94, 0x24, 0x90, 0x00, 0x00, 0x00, 0x33, 0xC9, 0xFF,
	0x94, 0x24, 0xC8, 0x00, 0x00, 0x00, 0x33, 0xC0, 0x48, 0x81, 0xC4, 0xF8, 0x00, 0x00, 0x00, 0xC3,
	0x48, 0x89, 0x54, 0x24, 0x10, 0x48, 0x89, 0x4C, 0x24, 0x08, 0x48, 0x83, 0xEC, 0x78, 0x48, 0x8B,
	0x84, 0x24, 0x80, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x30, 0x48, 0x8B, 0x44, 0x24, 0x30,
	0x0F, 0xB7, 0x00, 0x3D, 0x4D, 0x5A, 0x00, 0x00, 0x74, 0x07, 0x33, 0xC0, 0xE9, 0x04, 0x02, 0x00,
	0x00, 0x48, 0x8B, 0x44, 0x24, 0x30, 0x48, 0x63, 0x40, 0x3C, 0x48, 0x8B, 0x8C, 0x24, 0x80, 0x00,
	0x00, 0x00, 0x48, 0x03, 0xC8, 0x48, 0x8B, 0xC1, 0x48, 0x89, 0x44, 0x24, 0x40, 0xB8, 0x08, 0x00,
	0x00, 0x00, 0x48, 0x6B, 0xC0, 0x00, 0x48, 0x8B, 0x4C, 0x24, 0x40, 0x48, 0x8D, 0x84, 0x01, 0x88,
	0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x38, 0x48, 0x8B, 0x44, 0x24, 0x38, 0x8B, 0x00, 0x48,
	0x85, 0xC0, 0x75, 0x07, 0x33, 0xC0, 0xE9, 0xBA, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x38,
	0x8B, 0x00, 0x89, 0x44, 0x24, 0x18, 0x8B, 0x44, 0x24, 0x18, 0x48, 0x03, 0x84, 0x24, 0x80, 0x00,
	0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x10, 0x48, 0x8B, 0x44, 0x24, 0x10, 0x8B, 0x40, 0x18, 0x48,
	0x89, 0x44, 0x24, 0x48, 0x48, 0x8B, 0x44, 0x24, 0x10, 0x8B, 0x40, 0x1C, 0x89, 0x44, 0x24, 0x24,
	0x48, 0x8B, 0x44, 0x24, 0x10, 0x8B, 0x40, 0x20, 0x89, 0x44, 0x24, 0x1C, 0x48, 0x8B, 0x44, 0x24,
	0x10, 0x8B, 0x40, 0x24, 0x89, 0x44, 0x24, 0x20, 0x48, 0xC7, 0x44, 0x24, 0x08, 0x00, 0x00, 0x00,
	0x00, 0xEB, 0x0D, 0x48, 0x8B, 0x44, 0x24, 0x08, 0x48, 0xFF, 0xC0, 0x48, 0x89, 0x44, 0x24, 0x08,
	0x48, 0x8B, 0x44, 0x24, 0x48, 0x48, 0x39, 0x44, 0x24, 0x08, 0x0F, 0x83, 0x43, 0x01, 0x00, 0x00,
	0x8B, 0x44, 0x24, 0x1C, 0x48, 0x8B, 0x8C, 0x24, 0x80, 0x00, 0x00, 0x00, 0x48, 0x03, 0xC8, 0x48,
	0x8B, 0xC1, 0x48, 0x8B, 0x4C, 0x24, 0x08, 0x48, 0x8D, 0x04, 0x88, 0x48, 0x89, 0x44, 0x24, 0x58,
	0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x8C, 0x24, 0x80, 0x00, 0x00, 0x00, 0x48, 0x03, 0xC8, 0x48,
	0x8B, 0xC1, 0x48, 0x8B, 0x4C, 0x24, 0x08, 0x48, 0x8D, 0x04, 0x48, 0x48, 0x89, 0x44, 0x24, 0x50,
	0x8B, 0x44, 0x24, 0x24, 0x48, 0x8B, 0x8C, 0x24, 0x80, 0x00, 0x00, 0x00, 0x48, 0x03, 0xC8, 0x48,
	0x8B, 0xC1, 0x48, 0x8B, 0x4C, 0x24, 0x50, 0x0F, 0xB7, 0x09, 0x48, 0x8D, 0x04, 0x88, 0x48, 0x89,
	0x44, 0x24, 0x60, 0x48, 0x8B, 0x44, 0x24, 0x58, 0x8B, 0x00, 0x48, 0x8B, 0x8C, 0x24, 0x80, 0x00,
	0x00, 0x00, 0x48, 0x03, 0xC8, 0x48, 0x8B, 0xC1, 0x48, 0x89, 0x44, 0x24, 0x28, 0x48, 0xC7, 0x04,
	0x24, 0x00, 0x00, 0x00, 0x00, 0x48, 0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x0B, 0x48,
	0x8B, 0x04, 0x24, 0x48, 0xFF, 0xC0, 0x48, 0x89, 0x04, 0x24, 0x48, 0x8B, 0x04, 0x24, 0x48, 0x8B,
	0x8C, 0x24, 0x88, 0x00, 0x00, 0x00, 0x48, 0x03, 0xC8, 0x48, 0x8B, 0xC1, 0x0F, 0xBE, 0x00, 0x85,
	0xC0, 0x74, 0x45, 0x48, 0x8B, 0x04, 0x24, 0x48, 0x8B, 0x4C, 0x24, 0x28, 0x48, 0x03, 0xC8, 0x48,
	0x8B, 0xC1, 0x0F, 0xBE, 0x00, 0x85, 0xC0, 0x74, 0x2F, 0x48, 0x8B, 0x04, 0x24, 0x48, 0x8B, 0x8C,
	0x24, 0x88, 0x00, 0x00, 0x00, 0x48, 0x03, 0xC8, 0x48, 0x8B, 0xC1, 0x0F, 0xBE, 0x00, 0x48, 0x8B,
	0x0C, 0x24, 0x48, 0x8B, 0x54, 0x24, 0x28, 0x48, 0x03, 0xD1, 0x48, 0x8B, 0xCA, 0x0F, 0xBE, 0x09,
	0x3B, 0xC1, 0x74, 0x02, 0xEB, 0x02, 0xEB, 0x97, 0x48, 0x8B, 0x04, 0x24, 0x48, 0x8B, 0x8C, 0x24,
	0x88, 0x00, 0x00, 0x00, 0x48, 0x03, 0xC8, 0x48, 0x8B, 0xC1, 0x0F, 0xBE, 0x00, 0x85, 0xC0, 0x75,
	0x2D, 0x48, 0x8B, 0x04, 0x24, 0x48, 0x8B, 0x4C, 0x24, 0x28, 0x48, 0x03, 0xC8, 0x48, 0x8B, 0xC1,
	0x0F, 0xBE, 0x00, 0x85, 0xC0, 0x75, 0x17, 0x48, 0x8B, 0x44, 0x24, 0x60, 0x8B, 0x00, 0x48, 0x8B,
	0x8C, 0x24, 0x80, 0x00, 0x00, 0x00, 0x48, 0x03, 0xC8, 0x48, 0x8B, 0xC1, 0xEB, 0x07, 0xE9, 0xA0,
	0xFE, 0xFF, 0xFF, 0x33, 0xC0, 0x48, 0x83, 0xC4, 0x78, 0xC3, 0x48, 0x89, 0x4C, 0x24, 0x08, 0x56,
	0x57, 0x48, 0x83, 0xEC, 0x68, 0x48, 0xC7, 0x44, 0x24, 0x30, 0x00, 0x00, 0x00, 0x00, 0x65, 0x48,
	0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x30, 0x48, 0x8B, 0x44, 0x24,
	0x30, 0x48, 0x8B, 0x40, 0x18, 0x48, 0x89, 0x44, 0x24, 0x38, 0x48, 0x8D, 0x44, 0x24, 0x48, 0x48,
	0x8B, 0x4C, 0x24, 0x38, 0x48, 0x8B, 0xF8, 0x48, 0x8D, 0x71, 0x10, 0xB9, 0x10, 0x00, 0x00, 0x00,
	0xF3, 0xA4, 0x48, 0x8B, 0x44, 0x24, 0x48, 0x48, 0x89, 0x44, 0x24, 0x40, 0x48, 0x8B, 0x44, 0x24,
	0x40, 0x48, 0x89, 0x44, 0x24, 0x18, 0x48, 0x83, 0x7C, 0x24, 0x18, 0x00, 0x0F, 0x84, 0xC2, 0x01,
	0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x18, 0x48, 0x83, 0x78, 0x30, 0x00, 0x0F, 0x84, 0xB2, 0x01,
	0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x18, 0x48, 0x83, 0x78, 0x60, 0x00, 0x75, 0x02, 0xEB, 0xD6,
	0x48, 0x8B, 0x44, 0x24, 0x18, 0x48, 0x8B, 0x40, 0x60, 0x48, 0x89, 0x44, 0x24, 0x10, 0x48, 0xC7,
	0x04, 0x24, 0x00, 0x00, 0x00, 0x00, 0x48, 0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x0B,
	0x48, 0x8B, 0x04, 0x24, 0x48, 0xFF, 0xC0, 0x48, 0x89, 0x04, 0x24, 0x48, 0x8B, 0x84, 0x24, 0x80,
	0x00, 0x00, 0x00, 0x48, 0x8B, 0x0C, 0x24, 0x0F, 0xB7, 0x04, 0x48, 0x85, 0xC0, 0x0F, 0x84, 0x1F,
	0x01, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x10, 0x48, 0x8B, 0x0C, 0x24, 0x0F, 0xB7, 0x04, 0x48,
	0x85, 0xC0, 0x0F, 0x84, 0x0A, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00,
	0x48, 0x8B, 0x0C, 0x24, 0x0F, 0xB7, 0x04, 0x48, 0x83, 0xF8, 0x5A, 0x7F, 0x4F, 0x48, 0x8B, 0x84,
	0x24, 0x80, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x0C, 0x24, 0x0F, 0xB7, 0x04, 0x48, 0x83, 0xF8, 0x41,
	0x7C, 0x3A, 0x48, 0x8B, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x0C, 0x24, 0x0F, 0xB7,
	0x04, 0x48, 0x83, 0xE8, 0x41, 0x83, 0xC0, 0x61, 0x89, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x84, 0x24,
	0x80, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x0C, 0x24, 0x0F, 0xB7, 0x54, 0x24, 0x20, 0x66, 0x89, 0x14,
	0x48, 0x0F, 0xB7, 0x44, 0x24, 0x20, 0x89, 0x44, 0x24, 0x24, 0xEB, 0x14, 0x48, 0x8B, 0x84, 0x24,
	0x80, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x0C, 0x24, 0x0F, 0xB7, 0x04, 0x48, 0x89, 0x44, 0x24, 0x24,
	0x0F, 0xB7, 0x44, 0x24, 0x24, 0x66, 0x89, 0x44, 0x24, 0x08, 0x48, 0x8B, 0x44, 0x24, 0x10, 0x48,
	0x8B, 0x0C, 0x24, 0x0F, 0xB7, 0x04, 0x48, 0x83, 0xF8, 0x5A, 0x7F, 0x46, 0x48, 0x8B, 0x44, 0x24,
	0x10, 0x48, 0x8B, 0x0C, 0x24, 0x0F, 0xB7, 0x04, 0x48, 0x83, 0xF8, 0x41, 0x7C, 0x34, 0x48, 0x8B,
	0x44, 0x24, 0x10, 0x48, 0x8B, 0x0C, 0x24, 0x0F, 0xB7, 0x04, 0x48, 0x83, 0xE8, 0x41, 0x83, 0xC0,
	0x61, 0x89, 0x44, 0x24, 0x28, 0x48, 0x8B, 0x44, 0x24, 0x10, 0x48, 0x8B, 0x0C, 0x24, 0x0F, 0xB7,
	0x54, 0x24, 0x28, 0x66, 0x89, 0x14, 0x48, 0x0F, 0xB7, 0x44, 0x24, 0x28, 0x89, 0x44, 0x24, 0x2C,
	0xEB, 0x11, 0x48, 0x8B, 0x44, 0x24, 0x10, 0x48, 0x8B, 0x0C, 0x24, 0x0F, 0xB7, 0x04, 0x48, 0x89,
	0x44, 0x24, 0x2C, 0x0F, 0xB7, 0x44, 0x24, 0x2C, 0x66, 0x89, 0x44, 0x24, 0x0C, 0x0F, 0xB7, 0x44,
	0x24, 0x08, 0x0F, 0xB7, 0x4C, 0x24, 0x0C, 0x3B, 0xC1, 0x74, 0x02, 0xEB, 0x05, 0xE9, 0xBE, 0xFE,
	0xFF, 0xFF, 0x48, 0x8B, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x0C, 0x24, 0x0F, 0xB7,
	0x04, 0x48, 0x85, 0xC0, 0x75, 0x1C, 0x48, 0x8B, 0x44, 0x24, 0x10, 0x48, 0x8B, 0x0C, 0x24, 0x0F,
	0xB7, 0x04, 0x48, 0x85, 0xC0, 0x75, 0x0B, 0x48, 0x8B, 0x44, 0x24, 0x18, 0x48, 0x8B, 0x40, 0x30,
	0xEB, 0x14, 0x48, 0x8B, 0x44, 0x24, 0x18, 0x48, 0x8B, 0x00, 0x48, 0x89, 0x44, 0x24, 0x18, 0xE9,
	0x32, 0xFE, 0xFF, 0xFF, 0x33, 0xC0, 0x48, 0x83, 0xC4, 0x68, 0x5F, 0x5E, 0xC3
	};

// insert shellcode here


int main()
{
    printf("=== SHELLCODE TEST By OB ===\n");

    // Allocate memory with VirtualAlloc with RWX protection
    LPVOID allocatedMemory = VirtualAlloc(
        NULL,
        sizeof(text_section),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (allocatedMemory == NULL) {
        printf("Memory allocation failed with error: %d\n", GetLastError());
        return 1;
    }

    // Copy the shellcode to the allocated memory
    memcpy(allocatedMemory, text_section, sizeof(text_section));

    // Cast the allocated memory to a function pointer and execute it
    void (*shellcode)() = (void (*)())allocatedMemory;
    shellcode();

    // freeing the allocated memory
    if (!VirtualFree(allocatedMemory,0,MEM_RELEASE) ){
        return 1;
    }

    printf("=== Execution completed with no error ===\n");

    return 0;

}
