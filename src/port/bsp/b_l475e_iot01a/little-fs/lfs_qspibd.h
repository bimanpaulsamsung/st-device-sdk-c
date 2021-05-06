#ifndef LFS_QSPI_BD_H
#define LFS_QSPI_BD_H

#include "lfs.h"
#include "stm32l475e_iot01_qspi.h"

#ifdef __cplusplus
extern "C"
{
#endif

int QSPI_LFS_Config(void);

int qspi_lfs_mount(lfs_t *lfs);

int qspi_lfs_format(lfs_t *lfs);

#ifdef __cplusplus
}
#endif

#endif // LFS_QSPI_BD_H
