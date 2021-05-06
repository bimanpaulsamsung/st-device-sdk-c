#include "lfs.h"
#include "lfs_qspibd.h"
#include "stm32l475e_iot01_qspi.h"

static int block_device_read(const struct lfs_config *c, lfs_block_t block,
	lfs_off_t off, void *buffer, lfs_size_t size)
{
//	W25X_Read((uint8_t*)buffer, (block * c->block_size + off), size);
	BSP_QSPI_Read(buffer, (block * c->block_size + off), size);
	return 0;
}

static int block_device_prog(const struct lfs_config *c, lfs_block_t block,
	lfs_off_t off, const void *buffer, lfs_size_t size)
{
//	W25X_Write_NoCheck((uint8_t*)buffer, (block * c->block_size + off), size);
	BSP_QSPI_Write((uint8_t*)buffer, (block * c->block_size + off), size);
	return 0;
}

static int block_device_erase(const struct lfs_config *c, lfs_block_t block)
{
//	W25X_Erase_Sector(block * c->block_size);
	BSP_QSPI_Erase_Block(block);
	return 0;
}

static int block_device_sync(const struct lfs_config *c)
{
	return 0;
}

lfs_t lfs;
lfs_file_t file;
struct lfs_config cfg;

uint8_t lfs_read_buf[MX25R6435F_SECTOR_SIZE];
uint8_t lfs_prog_buf[MX25R6435F_SECTOR_SIZE];
uint8_t lfs_lookahead_buf[16];	// 128/8=16
uint8_t lfs_file_buf[256];

int QSPI_LFS_Config(void)
{
	// block device operations
	cfg.read  = block_device_read;
	cfg.prog  = block_device_prog;
	cfg.erase = block_device_erase;
	cfg.sync  = block_device_sync;

	// block device configuration
	cfg.read_size = MX25R6435F_SECTOR_SIZE;
	cfg.prog_size = MX25R6435F_SECTOR_SIZE;
	cfg.block_size = MX25R6435F_BLOCK_SIZE;
	cfg.block_count = MX25R6435F_FLASH_SIZE/MX25R6435F_BLOCK_SIZE;

	cfg.cache_size = MX25R6435F_SECTOR_SIZE;
	cfg.lookahead_size = MX25R6435F_SECTOR_SIZE;
	cfg.block_cycles = 500;


	cfg.read_buffer = lfs_read_buf;
	cfg.prog_buffer = lfs_prog_buf;
	cfg.lookahead_buffer = lfs_lookahead_buf;
//	cfg.file_buffer = lfs_file_buf;


	if (BSP_QSPI_Init() != 0) {
		return LFS_ERR_IO;
	}
	return 0;
}

int qspi_lfs_mount(lfs_t *lfs)
{
	return lfs_mount(lfs, &cfg);
}

int qspi_lfs_format(lfs_t *lfs)
{
	return lfs_format(lfs, &cfg);
}
