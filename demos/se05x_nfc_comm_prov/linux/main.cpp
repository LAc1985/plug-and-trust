/*
 * Copyright 2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <cstring>
#include "se05x_nfc_comm_prov.h"

int main(int argc, char *argv[])
{
   bool doReset = false;
   if (argc > 1 && strcmp(argv[1], "--reset") == 0)
   {
       doReset = true;
   }
   se05x_nfc_comm_prov(doReset);
   return 0;
}