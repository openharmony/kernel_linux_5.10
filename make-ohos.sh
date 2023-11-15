#!/bin/bash

set -e

SCRIPTPATH=$(dirname $realpath "$0")
export PATH=$(realpath $SCRIPTPATH/../../../../)/prebuilts/clang/ohos/linux-x86_64/llvm/bin/:$(realpath $SCRIPTPATH/../../../../)/prebuilts/develop_tools/pahole/bin/:$PATH
export PRODUCT_PATH=vendor/hihope/rk3568
IMAGE_SIZE=64  # 64M
IMAGE_BLOCKS=4096
ENABLE_LTO_O0=${3}

CPUs=`sed -n "N;/processor/p" /proc/cpuinfo|wc -l`
MAKE="make LLVM=1 LLVM_IAS=1 CROSS_COMPILE=aarch64-linux-gnu-"
[ "${ENABLE_LTO_O0}" == "enable_lto_O0" ] && MAKE="${MAKE} KCFLAGS=-Wl,--lto-O0"
BUILD_PATH=boot_linux
EXTLINUX_PATH=${BUILD_PATH}/extlinux
EXTLINUX_CONF=${EXTLINUX_PATH}/extlinux.conf
TOYBRICK_DTB=toybrick.dtb
if [ ${KBUILD_OUTPUT} ]; then
	OBJ_PATH=${KBUILD_OUTPUT}/
fi

ID_MODEL=1
ID_ARCH=2
ID_UART=3
ID_DTB=4
ID_IMAGE=5
ID_CONF=6
model_list=(
	"TB-RK3568X0   arm64 0xfe660000 rk3568-toybrick-x0-linux  Image rockchip_linux_defconfig"
	"TB-RK3568X10  arm64 0xfe660000 rk3568-toybrick-x10-linux Image rockchip_linux_defconfig"
)


function help()
{
	echo "Usage: ./make-ohos.sh {BOARD_NAME}"
	echo "e.g."
	for i in "${model_list[@]}"; do
		echo "  ./make-ohos.sh $(echo $i | awk '{print $1}')"
	done
}


function make_extlinux_conf()
{
	dtb_path=$1
	uart=$2
	image=$3
	
	echo "label rockchip-kernel-5.10" > ${EXTLINUX_CONF}
	echo "	kernel /extlinux/${image}" >> ${EXTLINUX_CONF}
	echo "	fdt /extlinux/${TOYBRICK_DTB}" >> ${EXTLINUX_CONF}
	cmdline="append earlycon=uart8250,mmio32,${uart} root=PARTUUID=614e0000-0000-4b53-8000-1d28000054a9 rw rootwait rootfstype=ext4"
	echo "  ${cmdline}" >> ${EXTLINUX_CONF}
}

function make_kernel_image()
{
	arch=$1
	conf=$2
	dtb=$3
	
	if [ "$GPUDRIVER" == "mesa3d" ]; then 
		config_base="arch/${arch}/configs/${conf}"
		config_frag="../../../../device/soc/rockchip/panfrost.config"
		ARCH=${arch} ./scripts/kconfig/merge_config.sh ${config_base} ${config_frag}
	else
		${MAKE} ARCH=${arch} ${conf}
	fi

	if [ $? -ne 0 ]; then
		echo "FAIL: ${MAKE} ARCH=${arch} ${conf}"
		return -1
	fi

	${MKEK} ARCH=${arch} modules_prepare
	if [ $? -ne 0 ]; then
		echo "FAIL: ${MAKE} ARCH=${arch} modules_prepare"
		return -2
	fi

	${MAKE} ARCH=${arch} ${dtb}.img -j${CPUs}
	if [ $? -ne 0 ]; then
		echo "FAIL: ${MAKE} ARCH=${arch} ${dtb}.img"
		return -2
	fi

	return 0
}

function make_ext2_image()
{
	blocks=${IMAGE_BLOCKS}
	block_size=$((${IMAGE_SIZE} * 1024 * 1024 / ${blocks}))

	if [ "`uname -m`" == "aarch64" ]; then
		echo y | sudo mke2fs -b ${block_size} -d boot_linux -i 8192 -t ext2 boot_linux.img ${blocks}
	else
		genext2fs -B ${blocks} -b ${block_size} -d boot_linux -i 8192 -U boot_linux.img
	fi

	return $?
}

function make_boot_linux()
{
	arch=${!ID_ARCH}
	uart=${!ID_UART}
	dtb=${!ID_DTB}
	image=${!ID_IMAGE}
	conf=${!ID_CONF}
	if [ ${arch} == "arm" ]; then
		dtb_path=arch/arm/boot/dts
	else
		dtb_path=arch/arm64/boot/dts/rockchip
	fi

	rm -rf ${BUILD_PATH}
	mkdir -p ${EXTLINUX_PATH}

	make_kernel_image ${arch} ${conf} ${dtb}
	if [ $? -ne 0 ]; then
		exit 1
	fi
	make_extlinux_conf ${dtb_path} ${uart} ${image}
	cp -f ${OBJ_PATH}arch/${arch}/boot/${image} ${EXTLINUX_PATH}/
	cp -f ${OBJ_PATH}${dtb_path}/${dtb}.dtb ${EXTLINUX_PATH}/${TOYBRICK_DTB}
	cp -f logo*.bmp ${BUILD_PATH}/
	if [ "enable_ramdisk" != "${ramdisk_flag}" ]; then
		make_ext2_image
	fi
}

ramdisk_flag=$2
found=0
for i in "${model_list[@]}"; do
	if [ "$(echo $i | awk '{print $1}')" == "$1" ]; then
		make_boot_linux $i
		found=1
	fi
done
