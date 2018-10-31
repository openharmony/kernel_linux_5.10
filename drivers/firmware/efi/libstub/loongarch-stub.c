// SPDX-License-Identifier: GPL-2.0
/*
 * Author: Yun Liu <liuyun@loongson.cn>
 *         Huacai Chen <chenhuacai@loongson.cn>
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */

#include <asm/efi.h>
#include <asm/addrspace.h>
#include "efistub.h"

#define BOOT_HEAP_SIZE 0x400000

typedef void __noreturn (*kernel_entry_t)(bool efi, unsigned long cmdline,
					  unsigned long systab);

extern long kernel_entaddr;
extern void decompress_kernel(unsigned long boot_heap_start);

static unsigned char efi_heap[BOOT_HEAP_SIZE];
static efi_guid_t screen_info_guid = LINUX_EFI_ARM_SCREEN_INFO_TABLE_GUID;
static kernel_entry_t kernel_entry;

struct screen_info *alloc_screen_info(void)
{
	efi_status_t status;
	struct screen_info *si;

	status = efi_bs_call(allocate_pool,
			EFI_RUNTIME_SERVICES_DATA, sizeof(*si), (void **)&si);
	if (status != EFI_SUCCESS)
		return NULL;

	memset(si, 0, sizeof(*si));

	status = efi_bs_call(install_configuration_table, &screen_info_guid, si);
	if (status == EFI_SUCCESS)
		return si;

	efi_bs_call(free_pool, si);

	return NULL;
}

void free_screen_info(struct screen_info *si)
{
	if (!si)
		return;

	efi_bs_call(install_configuration_table, &screen_info_guid, NULL);
	efi_bs_call(free_pool, si);
}

efi_status_t check_platform_features(void)
{
	return EFI_SUCCESS;
}

efi_status_t handle_kernel_image(unsigned long *image_addr,
				 unsigned long *image_size,
				 unsigned long *reserve_addr,
				 unsigned long *reserve_size,
				 efi_loaded_image_t *image)
{
	/* Config Direct Mapping */
	csr_write64(CSR_DMW0_INIT, LOONGARCH_CSR_DMWIN0);
	csr_write64(CSR_DMW1_INIT, LOONGARCH_CSR_DMWIN1);

	decompress_kernel((unsigned long)efi_heap);
	kernel_entry = (kernel_entry_t)kernel_entaddr;

	return EFI_SUCCESS;
}

struct exit_boot_struct {
	efi_memory_desc_t	*runtime_map;
	int			runtime_entry_count;
};

static efi_status_t exit_boot_func(struct efi_boot_memmap *map, void *priv)
{
	struct exit_boot_struct *p = priv;

	/*
	 * Update the memory map with virtual addresses. The function will also
	 * populate @runtime_map with copies of just the EFI_MEMORY_RUNTIME
	 * entries so that we can pass it straight to SetVirtualAddressMap()
	 */
	efi_get_virtmap(map->map, map->map_size, map->desc_size,
			p->runtime_map, &p->runtime_entry_count);

	return EFI_SUCCESS;
}

efi_status_t efi_boot_kernel(void *handle, efi_loaded_image_t *image,
			     unsigned long kernel_addr, char *cmdline_ptr)
{
	struct exit_boot_struct priv;
	unsigned long desc_size;
	efi_status_t status;
	u32 desc_ver;

	status = efi_alloc_virtmap(&priv.runtime_map, &desc_size, &desc_ver);
	if (status != EFI_SUCCESS) {
		efi_err("Unable to retrieve UEFI memory map.\n");
		return status;
	}

	efi_info("Exiting boot services\n");

	efi_novamap = false;
	status = efi_exit_boot_services(handle, &priv, exit_boot_func);
	if (status != EFI_SUCCESS)
		return status;

	/* Install the new virtual address map */
	efi_rt_call(set_virtual_address_map,
		    priv.runtime_entry_count * desc_size, desc_size,
		    desc_ver, priv.runtime_map);

	kernel_entry(true, (unsigned long)cmdline_ptr, (unsigned long)efi_system_table);
}
