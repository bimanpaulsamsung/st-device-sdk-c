/* ***************************************************************************
 *
 * Copyright 2019 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

const unsigned char st_root_ca[] = {
  0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x43,
  0x45, 0x52, 0x54, 0x49, 0x46, 0x49, 0x43, 0x41, 0x54, 0x45, 0x2d, 0x2d,
  0x2d, 0x2d, 0x2d, 0x0a, 0x4d, 0x49, 0x49, 0x44, 0x37, 0x7a, 0x43, 0x43,
  0x41, 0x74, 0x65, 0x67, 0x41, 0x77, 0x49, 0x42, 0x41, 0x67, 0x49, 0x42,
  0x41, 0x44, 0x41, 0x4e, 0x42, 0x67, 0x6b, 0x71, 0x68, 0x6b, 0x69, 0x47,
  0x39, 0x77, 0x30, 0x42, 0x41, 0x51, 0x73, 0x46, 0x41, 0x44, 0x43, 0x42,
  0x6d, 0x44, 0x45, 0x4c, 0x4d, 0x41, 0x6b, 0x47, 0x41, 0x31, 0x55, 0x45,
  0x42, 0x68, 0x4d, 0x43, 0x56, 0x56, 0x4d, 0x78, 0x0a, 0x45, 0x44, 0x41,
  0x4f, 0x42, 0x67, 0x4e, 0x56, 0x42, 0x41, 0x67, 0x54, 0x42, 0x30, 0x46,
  0x79, 0x61, 0x58, 0x70, 0x76, 0x62, 0x6d, 0x45, 0x78, 0x45, 0x7a, 0x41,
  0x52, 0x42, 0x67, 0x4e, 0x56, 0x42, 0x41, 0x63, 0x54, 0x43, 0x6c, 0x4e,
  0x6a, 0x62, 0x33, 0x52, 0x30, 0x63, 0x32, 0x52, 0x68, 0x62, 0x47, 0x55,
  0x78, 0x4a, 0x54, 0x41, 0x6a, 0x42, 0x67, 0x4e, 0x56, 0x42, 0x41, 0x6f,
  0x54, 0x0a, 0x48, 0x46, 0x4e, 0x30, 0x59, 0x58, 0x4a, 0x6d, 0x61, 0x57,
  0x56, 0x73, 0x5a, 0x43, 0x42, 0x55, 0x5a, 0x57, 0x4e, 0x6f, 0x62, 0x6d,
  0x39, 0x73, 0x62, 0x32, 0x64, 0x70, 0x5a, 0x58, 0x4d, 0x73, 0x49, 0x45,
  0x6c, 0x75, 0x59, 0x79, 0x34, 0x78, 0x4f, 0x7a, 0x41, 0x35, 0x42, 0x67,
  0x4e, 0x56, 0x42, 0x41, 0x4d, 0x54, 0x4d, 0x6c, 0x4e, 0x30, 0x59, 0x58,
  0x4a, 0x6d, 0x61, 0x57, 0x56, 0x73, 0x0a, 0x5a, 0x43, 0x42, 0x54, 0x5a,
  0x58, 0x4a, 0x32, 0x61, 0x57, 0x4e, 0x6c, 0x63, 0x79, 0x42, 0x53, 0x62,
  0x32, 0x39, 0x30, 0x49, 0x45, 0x4e, 0x6c, 0x63, 0x6e, 0x52, 0x70, 0x5a,
  0x6d, 0x6c, 0x6a, 0x59, 0x58, 0x52, 0x6c, 0x49, 0x45, 0x46, 0x31, 0x64,
  0x47, 0x68, 0x76, 0x63, 0x6d, 0x6c, 0x30, 0x65, 0x53, 0x41, 0x74, 0x49,
  0x45, 0x63, 0x79, 0x4d, 0x42, 0x34, 0x58, 0x44, 0x54, 0x41, 0x35, 0x0a,
  0x4d, 0x44, 0x6b, 0x77, 0x4d, 0x54, 0x41, 0x77, 0x4d, 0x44, 0x41, 0x77,
  0x4d, 0x46, 0x6f, 0x58, 0x44, 0x54, 0x4d, 0x33, 0x4d, 0x54, 0x49, 0x7a,
  0x4d, 0x54, 0x49, 0x7a, 0x4e, 0x54, 0x6b, 0x31, 0x4f, 0x56, 0x6f, 0x77,
  0x67, 0x5a, 0x67, 0x78, 0x43, 0x7a, 0x41, 0x4a, 0x42, 0x67, 0x4e, 0x56,
  0x42, 0x41, 0x59, 0x54, 0x41, 0x6c, 0x56, 0x54, 0x4d, 0x52, 0x41, 0x77,
  0x44, 0x67, 0x59, 0x44, 0x0a, 0x56, 0x51, 0x51, 0x49, 0x45, 0x77, 0x64,
  0x42, 0x63, 0x6d, 0x6c, 0x36, 0x62, 0x32, 0x35, 0x68, 0x4d, 0x52, 0x4d,
  0x77, 0x45, 0x51, 0x59, 0x44, 0x56, 0x51, 0x51, 0x48, 0x45, 0x77, 0x70,
  0x54, 0x59, 0x32, 0x39, 0x30, 0x64, 0x48, 0x4e, 0x6b, 0x59, 0x57, 0x78,
  0x6c, 0x4d, 0x53, 0x55, 0x77, 0x49, 0x77, 0x59, 0x44, 0x56, 0x51, 0x51,
  0x4b, 0x45, 0x78, 0x78, 0x54, 0x64, 0x47, 0x46, 0x79, 0x0a, 0x5a, 0x6d,
  0x6c, 0x6c, 0x62, 0x47, 0x51, 0x67, 0x56, 0x47, 0x56, 0x6a, 0x61, 0x47,
  0x35, 0x76, 0x62, 0x47, 0x39, 0x6e, 0x61, 0x57, 0x56, 0x7a, 0x4c, 0x43,
  0x42, 0x4a, 0x62, 0x6d, 0x4d, 0x75, 0x4d, 0x54, 0x73, 0x77, 0x4f, 0x51,
  0x59, 0x44, 0x56, 0x51, 0x51, 0x44, 0x45, 0x7a, 0x4a, 0x54, 0x64, 0x47,
  0x46, 0x79, 0x5a, 0x6d, 0x6c, 0x6c, 0x62, 0x47, 0x51, 0x67, 0x55, 0x32,
  0x56, 0x79, 0x0a, 0x64, 0x6d, 0x6c, 0x6a, 0x5a, 0x58, 0x4d, 0x67, 0x55,
  0x6d, 0x39, 0x76, 0x64, 0x43, 0x42, 0x44, 0x5a, 0x58, 0x4a, 0x30, 0x61,
  0x57, 0x5a, 0x70, 0x59, 0x32, 0x46, 0x30, 0x5a, 0x53, 0x42, 0x42, 0x64,
  0x58, 0x52, 0x6f, 0x62, 0x33, 0x4a, 0x70, 0x64, 0x48, 0x6b, 0x67, 0x4c,
  0x53, 0x42, 0x48, 0x4d, 0x6a, 0x43, 0x43, 0x41, 0x53, 0x49, 0x77, 0x44,
  0x51, 0x59, 0x4a, 0x4b, 0x6f, 0x5a, 0x49, 0x0a, 0x68, 0x76, 0x63, 0x4e,
  0x41, 0x51, 0x45, 0x42, 0x42, 0x51, 0x41, 0x44, 0x67, 0x67, 0x45, 0x50,
  0x41, 0x44, 0x43, 0x43, 0x41, 0x51, 0x6f, 0x43, 0x67, 0x67, 0x45, 0x42,
  0x41, 0x4e, 0x55, 0x4d, 0x4f, 0x73, 0x51, 0x71, 0x2b, 0x55, 0x37, 0x69,
  0x39, 0x62, 0x34, 0x5a, 0x6c, 0x31, 0x2b, 0x4f, 0x69, 0x46, 0x4f, 0x78,
  0x48, 0x7a, 0x2f, 0x4c, 0x7a, 0x35, 0x38, 0x67, 0x45, 0x32, 0x30, 0x70,
  0x0a, 0x4f, 0x73, 0x67, 0x50, 0x66, 0x54, 0x7a, 0x33, 0x61, 0x33, 0x59,
  0x34, 0x59, 0x39, 0x6b, 0x32, 0x59, 0x4b, 0x69, 0x62, 0x58, 0x6c, 0x77,
  0x41, 0x67, 0x4c, 0x49, 0x76, 0x57, 0x58, 0x2f, 0x32, 0x68, 0x2f, 0x6b,
  0x6c, 0x51, 0x34, 0x62, 0x6e, 0x61, 0x52, 0x74, 0x53, 0x6d, 0x70, 0x44,
  0x68, 0x63, 0x65, 0x50, 0x59, 0x4c, 0x51, 0x31, 0x4f, 0x62, 0x2f, 0x62,
  0x49, 0x53, 0x64, 0x6d, 0x32, 0x0a, 0x38, 0x78, 0x70, 0x57, 0x72, 0x69,
  0x75, 0x32, 0x64, 0x42, 0x54, 0x72, 0x7a, 0x2f, 0x73, 0x6d, 0x34, 0x78,
  0x71, 0x36, 0x48, 0x5a, 0x59, 0x75, 0x61, 0x6a, 0x74, 0x59, 0x6c, 0x49,
  0x6c, 0x48, 0x56, 0x76, 0x38, 0x6c, 0x6f, 0x4a, 0x4e, 0x77, 0x55, 0x34,
  0x50, 0x61, 0x68, 0x48, 0x51, 0x55, 0x77, 0x32, 0x65, 0x65, 0x42, 0x47,
  0x67, 0x36, 0x33, 0x34, 0x35, 0x41, 0x57, 0x68, 0x31, 0x4b, 0x0a, 0x54,
  0x73, 0x39, 0x44, 0x6b, 0x54, 0x76, 0x6e, 0x56, 0x74, 0x59, 0x41, 0x63,
  0x4d, 0x74, 0x53, 0x37, 0x6e, 0x74, 0x39, 0x72, 0x6a, 0x72, 0x6e, 0x76,
  0x44, 0x48, 0x35, 0x52, 0x66, 0x62, 0x43, 0x59, 0x4d, 0x38, 0x54, 0x57,
  0x51, 0x49, 0x72, 0x67, 0x4d, 0x77, 0x30, 0x52, 0x39, 0x2b, 0x35, 0x33,
  0x70, 0x42, 0x6c, 0x62, 0x51, 0x4c, 0x50, 0x4c, 0x4a, 0x47, 0x6d, 0x70,
  0x75, 0x66, 0x65, 0x0a, 0x68, 0x52, 0x68, 0x4a, 0x66, 0x47, 0x5a, 0x4f,
  0x6f, 0x7a, 0x70, 0x74, 0x71, 0x62, 0x58, 0x75, 0x4e, 0x43, 0x36, 0x36,
  0x44, 0x51, 0x4f, 0x34, 0x4d, 0x39, 0x39, 0x48, 0x36, 0x37, 0x46, 0x72,
  0x6a, 0x53, 0x58, 0x5a, 0x6d, 0x38, 0x36, 0x42, 0x30, 0x55, 0x56, 0x47,
  0x4d, 0x70, 0x5a, 0x77, 0x68, 0x39, 0x34, 0x43, 0x44, 0x6b, 0x6c, 0x44,
  0x68, 0x62, 0x5a, 0x73, 0x63, 0x37, 0x74, 0x6b, 0x0a, 0x36, 0x6d, 0x46,
  0x42, 0x72, 0x4d, 0x6e, 0x55, 0x56, 0x4e, 0x2b, 0x48, 0x4c, 0x38, 0x63,
  0x69, 0x73, 0x69, 0x62, 0x4d, 0x6e, 0x31, 0x6c, 0x55, 0x61, 0x4a, 0x2f,
  0x38, 0x76, 0x69, 0x6f, 0x76, 0x78, 0x46, 0x55, 0x63, 0x64, 0x55, 0x42,
  0x67, 0x46, 0x34, 0x55, 0x43, 0x56, 0x54, 0x6d, 0x4c, 0x66, 0x77, 0x55,
  0x43, 0x41, 0x77, 0x45, 0x41, 0x41, 0x61, 0x4e, 0x43, 0x4d, 0x45, 0x41,
  0x77, 0x0a, 0x44, 0x77, 0x59, 0x44, 0x56, 0x52, 0x30, 0x54, 0x41, 0x51,
  0x48, 0x2f, 0x42, 0x41, 0x55, 0x77, 0x41, 0x77, 0x45, 0x42, 0x2f, 0x7a,
  0x41, 0x4f, 0x42, 0x67, 0x4e, 0x56, 0x48, 0x51, 0x38, 0x42, 0x41, 0x66,
  0x38, 0x45, 0x42, 0x41, 0x4d, 0x43, 0x41, 0x51, 0x59, 0x77, 0x48, 0x51,
  0x59, 0x44, 0x56, 0x52, 0x30, 0x4f, 0x42, 0x42, 0x59, 0x45, 0x46, 0x4a,
  0x78, 0x66, 0x41, 0x4e, 0x2b, 0x71, 0x0a, 0x41, 0x64, 0x63, 0x77, 0x4b,
  0x7a, 0x69, 0x49, 0x6f, 0x72, 0x68, 0x74, 0x53, 0x70, 0x7a, 0x79, 0x45,
  0x5a, 0x47, 0x44, 0x4d, 0x41, 0x30, 0x47, 0x43, 0x53, 0x71, 0x47, 0x53,
  0x49, 0x62, 0x33, 0x44, 0x51, 0x45, 0x42, 0x43, 0x77, 0x55, 0x41, 0x41,
  0x34, 0x49, 0x42, 0x41, 0x51, 0x42, 0x4c, 0x4e, 0x71, 0x61, 0x45, 0x64,
  0x32, 0x6e, 0x64, 0x4f, 0x78, 0x6d, 0x66, 0x5a, 0x79, 0x4d, 0x49, 0x0a,
  0x62, 0x77, 0x35, 0x68, 0x79, 0x66, 0x32, 0x45, 0x33, 0x46, 0x2f, 0x59,
  0x4e, 0x6f, 0x48, 0x4e, 0x32, 0x42, 0x74, 0x42, 0x4c, 0x5a, 0x39, 0x67,
  0x33, 0x63, 0x63, 0x61, 0x61, 0x4e, 0x6e, 0x52, 0x62, 0x6f, 0x62, 0x68,
  0x69, 0x43, 0x50, 0x50, 0x45, 0x39, 0x35, 0x44, 0x7a, 0x2b, 0x49, 0x30,
  0x73, 0x77, 0x53, 0x64, 0x48, 0x79, 0x6e, 0x56, 0x76, 0x2f, 0x68, 0x65,
  0x79, 0x4e, 0x58, 0x42, 0x0a, 0x76, 0x65, 0x36, 0x53, 0x62, 0x7a, 0x4a,
  0x30, 0x38, 0x70, 0x47, 0x43, 0x4c, 0x37, 0x32, 0x43, 0x51, 0x6e, 0x71,
  0x74, 0x4b, 0x72, 0x63, 0x67, 0x66, 0x55, 0x32, 0x38, 0x65, 0x6c, 0x55,
  0x53, 0x77, 0x68, 0x58, 0x71, 0x76, 0x66, 0x64, 0x71, 0x6c, 0x53, 0x35,
  0x73, 0x64, 0x4a, 0x2f, 0x50, 0x48, 0x4c, 0x54, 0x79, 0x78, 0x51, 0x47,
  0x6a, 0x68, 0x64, 0x42, 0x79, 0x50, 0x71, 0x31, 0x7a, 0x0a, 0x71, 0x77,
  0x75, 0x62, 0x64, 0x51, 0x78, 0x74, 0x52, 0x62, 0x65, 0x4f, 0x6c, 0x4b,
  0x79, 0x57, 0x4e, 0x37, 0x57, 0x67, 0x30, 0x49, 0x38, 0x56, 0x52, 0x77,
  0x37, 0x6a, 0x36, 0x49, 0x50, 0x64, 0x6a, 0x2f, 0x33, 0x76, 0x51, 0x51,
  0x46, 0x33, 0x7a, 0x43, 0x65, 0x70, 0x59, 0x6f, 0x55, 0x7a, 0x38, 0x6a,
  0x63, 0x49, 0x37, 0x33, 0x48, 0x50, 0x64, 0x77, 0x62, 0x65, 0x79, 0x42,
  0x6b, 0x64, 0x0a, 0x69, 0x45, 0x44, 0x50, 0x66, 0x55, 0x59, 0x64, 0x2f,
  0x78, 0x37, 0x48, 0x34, 0x63, 0x37, 0x2f, 0x49, 0x39, 0x76, 0x47, 0x2b,
  0x6f, 0x31, 0x56, 0x54, 0x71, 0x6b, 0x43, 0x35, 0x30, 0x63, 0x52, 0x52,
  0x6a, 0x37, 0x30, 0x2f, 0x62, 0x31, 0x37, 0x4b, 0x53, 0x61, 0x37, 0x71,
  0x57, 0x46, 0x69, 0x4e, 0x79, 0x69, 0x32, 0x4c, 0x53, 0x72, 0x32, 0x45,
  0x49, 0x5a, 0x6b, 0x79, 0x58, 0x43, 0x6e, 0x0a, 0x30, 0x71, 0x32, 0x33,
  0x4b, 0x58, 0x42, 0x35, 0x36, 0x6a, 0x7a, 0x61, 0x59, 0x79, 0x57, 0x66,
  0x2f, 0x57, 0x69, 0x33, 0x4d, 0x4f, 0x78, 0x77, 0x2b, 0x33, 0x57, 0x4b,
  0x74, 0x32, 0x31, 0x67, 0x5a, 0x37, 0x49, 0x65, 0x79, 0x4c, 0x6e, 0x70,
  0x32, 0x4b, 0x68, 0x76, 0x41, 0x6f, 0x74, 0x6e, 0x44, 0x55, 0x30, 0x6d,
  0x56, 0x33, 0x48, 0x61, 0x49, 0x50, 0x7a, 0x42, 0x53, 0x6c, 0x43, 0x4e,
  0x0a, 0x73, 0x53, 0x69, 0x36, 0x0a, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x45,
  0x4e, 0x44, 0x20, 0x43, 0x45, 0x52, 0x54, 0x49, 0x46, 0x49, 0x43, 0x41,
  0x54, 0x45, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a, 0x2d, 0x2d, 0x2d, 0x2d,
  0x2d, 0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x43, 0x45, 0x52, 0x54, 0x49,
  0x46, 0x49, 0x43, 0x41, 0x54, 0x45, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a,
  0x4d, 0x49, 0x49, 0x44, 0x72, 0x7a, 0x43, 0x43, 0x41, 0x70, 0x65, 0x67,
  0x41, 0x77, 0x49, 0x42, 0x41, 0x67, 0x49, 0x51, 0x43, 0x44, 0x76, 0x67,
  0x56, 0x70, 0x42, 0x43, 0x52, 0x72, 0x47, 0x68, 0x64, 0x57, 0x72, 0x4a,
  0x57, 0x5a, 0x48, 0x48, 0x53, 0x6a, 0x41, 0x4e, 0x42, 0x67, 0x6b, 0x71,
  0x68, 0x6b, 0x69, 0x47, 0x39, 0x77, 0x30, 0x42, 0x41, 0x51, 0x55, 0x46,
  0x41, 0x44, 0x42, 0x68, 0x0a, 0x4d, 0x51, 0x73, 0x77, 0x43, 0x51, 0x59,
  0x44, 0x56, 0x51, 0x51, 0x47, 0x45, 0x77, 0x4a, 0x56, 0x55, 0x7a, 0x45,
  0x56, 0x4d, 0x42, 0x4d, 0x47, 0x41, 0x31, 0x55, 0x45, 0x43, 0x68, 0x4d,
  0x4d, 0x52, 0x47, 0x6c, 0x6e, 0x61, 0x55, 0x4e, 0x6c, 0x63, 0x6e, 0x51,
  0x67, 0x53, 0x57, 0x35, 0x6a, 0x4d, 0x52, 0x6b, 0x77, 0x46, 0x77, 0x59,
  0x44, 0x56, 0x51, 0x51, 0x4c, 0x45, 0x78, 0x42, 0x33, 0x0a, 0x64, 0x33,
  0x63, 0x75, 0x5a, 0x47, 0x6c, 0x6e, 0x61, 0x57, 0x4e, 0x6c, 0x63, 0x6e,
  0x51, 0x75, 0x59, 0x32, 0x39, 0x74, 0x4d, 0x53, 0x41, 0x77, 0x48, 0x67,
  0x59, 0x44, 0x56, 0x51, 0x51, 0x44, 0x45, 0x78, 0x64, 0x45, 0x61, 0x57,
  0x64, 0x70, 0x51, 0x32, 0x56, 0x79, 0x64, 0x43, 0x42, 0x48, 0x62, 0x47,
  0x39, 0x69, 0x59, 0x57, 0x77, 0x67, 0x55, 0x6d, 0x39, 0x76, 0x64, 0x43,
  0x42, 0x44, 0x0a, 0x51, 0x54, 0x41, 0x65, 0x46, 0x77, 0x30, 0x77, 0x4e,
  0x6a, 0x45, 0x78, 0x4d, 0x54, 0x41, 0x77, 0x4d, 0x44, 0x41, 0x77, 0x4d,
  0x44, 0x42, 0x61, 0x46, 0x77, 0x30, 0x7a, 0x4d, 0x54, 0x45, 0x78, 0x4d,
  0x54, 0x41, 0x77, 0x4d, 0x44, 0x41, 0x77, 0x4d, 0x44, 0x42, 0x61, 0x4d,
  0x47, 0x45, 0x78, 0x43, 0x7a, 0x41, 0x4a, 0x42, 0x67, 0x4e, 0x56, 0x42,
  0x41, 0x59, 0x54, 0x41, 0x6c, 0x56, 0x54, 0x0a, 0x4d, 0x52, 0x55, 0x77,
  0x45, 0x77, 0x59, 0x44, 0x56, 0x51, 0x51, 0x4b, 0x45, 0x77, 0x78, 0x45,
  0x61, 0x57, 0x64, 0x70, 0x51, 0x32, 0x56, 0x79, 0x64, 0x43, 0x42, 0x4a,
  0x62, 0x6d, 0x4d, 0x78, 0x47, 0x54, 0x41, 0x58, 0x42, 0x67, 0x4e, 0x56,
  0x42, 0x41, 0x73, 0x54, 0x45, 0x48, 0x64, 0x33, 0x64, 0x79, 0x35, 0x6b,
  0x61, 0x57, 0x64, 0x70, 0x59, 0x32, 0x56, 0x79, 0x64, 0x43, 0x35, 0x6a,
  0x0a, 0x62, 0x32, 0x30, 0x78, 0x49, 0x44, 0x41, 0x65, 0x42, 0x67, 0x4e,
  0x56, 0x42, 0x41, 0x4d, 0x54, 0x46, 0x30, 0x52, 0x70, 0x5a, 0x32, 0x6c,
  0x44, 0x5a, 0x58, 0x4a, 0x30, 0x49, 0x45, 0x64, 0x73, 0x62, 0x32, 0x4a,
  0x68, 0x62, 0x43, 0x42, 0x53, 0x62, 0x32, 0x39, 0x30, 0x49, 0x45, 0x4e,
  0x42, 0x4d, 0x49, 0x49, 0x42, 0x49, 0x6a, 0x41, 0x4e, 0x42, 0x67, 0x6b,
  0x71, 0x68, 0x6b, 0x69, 0x47, 0x0a, 0x39, 0x77, 0x30, 0x42, 0x41, 0x51,
  0x45, 0x46, 0x41, 0x41, 0x4f, 0x43, 0x41, 0x51, 0x38, 0x41, 0x4d, 0x49,
  0x49, 0x42, 0x43, 0x67, 0x4b, 0x43, 0x41, 0x51, 0x45, 0x41, 0x34, 0x6a,
  0x76, 0x68, 0x45, 0x58, 0x4c, 0x65, 0x71, 0x4b, 0x54, 0x54, 0x6f, 0x31,
  0x65, 0x71, 0x55, 0x4b, 0x4b, 0x50, 0x43, 0x33, 0x65, 0x51, 0x79, 0x61,
  0x4b, 0x6c, 0x37, 0x68, 0x4c, 0x4f, 0x6c, 0x6c, 0x73, 0x42, 0x0a, 0x43,
  0x53, 0x44, 0x4d, 0x41, 0x5a, 0x4f, 0x6e, 0x54, 0x6a, 0x43, 0x33, 0x55,
  0x2f, 0x64, 0x44, 0x78, 0x47, 0x6b, 0x41, 0x56, 0x35, 0x33, 0x69, 0x6a,
  0x53, 0x4c, 0x64, 0x68, 0x77, 0x5a, 0x41, 0x41, 0x49, 0x45, 0x4a, 0x7a,
  0x73, 0x34, 0x62, 0x67, 0x37, 0x2f, 0x66, 0x7a, 0x54, 0x74, 0x78, 0x52,
  0x75, 0x4c, 0x57, 0x5a, 0x73, 0x63, 0x46, 0x73, 0x33, 0x59, 0x6e, 0x46,
  0x6f, 0x39, 0x37, 0x0a, 0x6e, 0x68, 0x36, 0x56, 0x66, 0x65, 0x36, 0x33,
  0x53, 0x4b, 0x4d, 0x49, 0x32, 0x74, 0x61, 0x76, 0x65, 0x67, 0x77, 0x35,
  0x42, 0x6d, 0x56, 0x2f, 0x53, 0x6c, 0x30, 0x66, 0x76, 0x42, 0x66, 0x34,
  0x71, 0x37, 0x37, 0x75, 0x4b, 0x4e, 0x64, 0x30, 0x66, 0x33, 0x70, 0x34,
  0x6d, 0x56, 0x6d, 0x46, 0x61, 0x47, 0x35, 0x63, 0x49, 0x7a, 0x4a, 0x4c,
  0x76, 0x30, 0x37, 0x41, 0x36, 0x46, 0x70, 0x74, 0x0a, 0x34, 0x33, 0x43,
  0x2f, 0x64, 0x78, 0x43, 0x2f, 0x2f, 0x41, 0x48, 0x32, 0x68, 0x64, 0x6d,
  0x6f, 0x52, 0x42, 0x42, 0x59, 0x4d, 0x71, 0x6c, 0x31, 0x47, 0x4e, 0x58,
  0x52, 0x6f, 0x72, 0x35, 0x48, 0x34, 0x69, 0x64, 0x71, 0x39, 0x4a, 0x6f,
  0x7a, 0x2b, 0x45, 0x6b, 0x49, 0x59, 0x49, 0x76, 0x55, 0x58, 0x37, 0x51,
  0x36, 0x68, 0x4c, 0x2b, 0x68, 0x71, 0x6b, 0x70, 0x4d, 0x66, 0x54, 0x37,
  0x50, 0x0a, 0x54, 0x31, 0x39, 0x73, 0x64, 0x6c, 0x36, 0x67, 0x53, 0x7a,
  0x65, 0x52, 0x6e, 0x74, 0x77, 0x69, 0x35, 0x6d, 0x33, 0x4f, 0x46, 0x42,
  0x71, 0x4f, 0x61, 0x73, 0x76, 0x2b, 0x7a, 0x62, 0x4d, 0x55, 0x5a, 0x42,
  0x66, 0x48, 0x57, 0x79, 0x6d, 0x65, 0x4d, 0x72, 0x2f, 0x79, 0x37, 0x76,
  0x72, 0x54, 0x43, 0x30, 0x4c, 0x55, 0x71, 0x37, 0x64, 0x42, 0x4d, 0x74,
  0x6f, 0x4d, 0x31, 0x4f, 0x2f, 0x34, 0x0a, 0x67, 0x64, 0x57, 0x37, 0x6a,
  0x56, 0x67, 0x2f, 0x74, 0x52, 0x76, 0x6f, 0x53, 0x53, 0x69, 0x69, 0x63,
  0x4e, 0x6f, 0x78, 0x42, 0x4e, 0x33, 0x33, 0x73, 0x68, 0x62, 0x79, 0x54,
  0x41, 0x70, 0x4f, 0x42, 0x36, 0x6a, 0x74, 0x53, 0x6a, 0x31, 0x65, 0x74,
  0x58, 0x2b, 0x6a, 0x6b, 0x4d, 0x4f, 0x76, 0x4a, 0x77, 0x49, 0x44, 0x41,
  0x51, 0x41, 0x42, 0x6f, 0x32, 0x4d, 0x77, 0x59, 0x54, 0x41, 0x4f, 0x0a,
  0x42, 0x67, 0x4e, 0x56, 0x48, 0x51, 0x38, 0x42, 0x41, 0x66, 0x38, 0x45,
  0x42, 0x41, 0x4d, 0x43, 0x41, 0x59, 0x59, 0x77, 0x44, 0x77, 0x59, 0x44,
  0x56, 0x52, 0x30, 0x54, 0x41, 0x51, 0x48, 0x2f, 0x42, 0x41, 0x55, 0x77,
  0x41, 0x77, 0x45, 0x42, 0x2f, 0x7a, 0x41, 0x64, 0x42, 0x67, 0x4e, 0x56,
  0x48, 0x51, 0x34, 0x45, 0x46, 0x67, 0x51, 0x55, 0x41, 0x39, 0x35, 0x51,
  0x4e, 0x56, 0x62, 0x52, 0x0a, 0x54, 0x4c, 0x74, 0x6d, 0x38, 0x4b, 0x50,
  0x69, 0x47, 0x78, 0x76, 0x44, 0x6c, 0x37, 0x49, 0x39, 0x30, 0x56, 0x55,
  0x77, 0x48, 0x77, 0x59, 0x44, 0x56, 0x52, 0x30, 0x6a, 0x42, 0x42, 0x67,
  0x77, 0x46, 0x6f, 0x41, 0x55, 0x41, 0x39, 0x35, 0x51, 0x4e, 0x56, 0x62,
  0x52, 0x54, 0x4c, 0x74, 0x6d, 0x38, 0x4b, 0x50, 0x69, 0x47, 0x78, 0x76,
  0x44, 0x6c, 0x37, 0x49, 0x39, 0x30, 0x56, 0x55, 0x77, 0x0a, 0x44, 0x51,
  0x59, 0x4a, 0x4b, 0x6f, 0x5a, 0x49, 0x68, 0x76, 0x63, 0x4e, 0x41, 0x51,
  0x45, 0x46, 0x42, 0x51, 0x41, 0x44, 0x67, 0x67, 0x45, 0x42, 0x41, 0x4d,
  0x75, 0x63, 0x4e, 0x36, 0x70, 0x49, 0x45, 0x78, 0x49, 0x4b, 0x2b, 0x74,
  0x31, 0x45, 0x6e, 0x45, 0x39, 0x53, 0x73, 0x50, 0x54, 0x66, 0x72, 0x67,
  0x54, 0x31, 0x65, 0x58, 0x6b, 0x49, 0x6f, 0x79, 0x51, 0x59, 0x2f, 0x45,
  0x73, 0x72, 0x0a, 0x68, 0x4d, 0x41, 0x74, 0x75, 0x64, 0x58, 0x48, 0x2f,
  0x76, 0x54, 0x42, 0x48, 0x31, 0x6a, 0x4c, 0x75, 0x47, 0x32, 0x63, 0x65,
  0x6e, 0x54, 0x6e, 0x6d, 0x43, 0x6d, 0x72, 0x45, 0x62, 0x58, 0x6a, 0x63,
  0x4b, 0x43, 0x68, 0x7a, 0x55, 0x79, 0x49, 0x6d, 0x5a, 0x4f, 0x4d, 0x6b,
  0x58, 0x44, 0x69, 0x71, 0x77, 0x38, 0x63, 0x76, 0x70, 0x4f, 0x70, 0x2f,
  0x32, 0x50, 0x56, 0x35, 0x41, 0x64, 0x67, 0x0a, 0x30, 0x36, 0x4f, 0x2f,
  0x6e, 0x56, 0x73, 0x4a, 0x38, 0x64, 0x57, 0x4f, 0x34, 0x31, 0x50, 0x30,
  0x6a, 0x6d, 0x50, 0x36, 0x50, 0x36, 0x66, 0x62, 0x74, 0x47, 0x62, 0x66,
  0x59, 0x6d, 0x62, 0x57, 0x30, 0x57, 0x35, 0x42, 0x6a, 0x66, 0x49, 0x74,
  0x74, 0x65, 0x70, 0x33, 0x53, 0x70, 0x2b, 0x64, 0x57, 0x4f, 0x49, 0x72,
  0x57, 0x63, 0x42, 0x41, 0x49, 0x2b, 0x30, 0x74, 0x4b, 0x49, 0x4a, 0x46,
  0x0a, 0x50, 0x6e, 0x6c, 0x55, 0x6b, 0x69, 0x61, 0x59, 0x34, 0x49, 0x42,
  0x49, 0x71, 0x44, 0x66, 0x76, 0x38, 0x4e, 0x5a, 0x35, 0x59, 0x42, 0x62,
  0x65, 0x72, 0x4f, 0x67, 0x4f, 0x7a, 0x57, 0x36, 0x73, 0x52, 0x42, 0x63,
  0x34, 0x4c, 0x30, 0x6e, 0x61, 0x34, 0x55, 0x55, 0x2b, 0x4b, 0x72, 0x6b,
  0x32, 0x55, 0x38, 0x38, 0x36, 0x55, 0x41, 0x62, 0x33, 0x4c, 0x75, 0x6a,
  0x45, 0x56, 0x30, 0x6c, 0x73, 0x0a, 0x59, 0x53, 0x45, 0x59, 0x31, 0x51,
  0x53, 0x74, 0x65, 0x44, 0x77, 0x73, 0x4f, 0x6f, 0x42, 0x72, 0x70, 0x2b,
  0x75, 0x76, 0x46, 0x52, 0x54, 0x70, 0x32, 0x49, 0x6e, 0x42, 0x75, 0x54,
  0x68, 0x73, 0x34, 0x70, 0x46, 0x73, 0x69, 0x76, 0x39, 0x6b, 0x75, 0x58,
  0x63, 0x6c, 0x56, 0x7a, 0x44, 0x41, 0x47, 0x79, 0x53, 0x6a, 0x34, 0x64,
  0x7a, 0x70, 0x33, 0x30, 0x64, 0x38, 0x74, 0x62, 0x51, 0x6b, 0x0a, 0x43,
  0x41, 0x55, 0x77, 0x37, 0x43, 0x32, 0x39, 0x43, 0x37, 0x39, 0x46, 0x76,
  0x31, 0x43, 0x35, 0x71, 0x66, 0x50, 0x72, 0x6d, 0x41, 0x45, 0x53, 0x72,
  0x63, 0x69, 0x49, 0x78, 0x70, 0x67, 0x30, 0x58, 0x34, 0x30, 0x4b, 0x50,
  0x4d, 0x62, 0x70, 0x31, 0x5a, 0x57, 0x56, 0x62, 0x64, 0x34, 0x3d, 0x0a,
  0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x45, 0x4e, 0x44, 0x20, 0x43, 0x45, 0x52,
  0x54, 0x49, 0x46, 0x49, 0x43, 0x41, 0x54, 0x45, 0x2d, 0x2d, 0x2d, 0x2d,
  0x2d, 0x0a
};
const unsigned int st_root_ca_len = 2762;
