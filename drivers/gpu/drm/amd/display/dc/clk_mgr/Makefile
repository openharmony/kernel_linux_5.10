#
# Copyright 2017 Advanced Micro Devices, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
# THE COPYRIGHT HOLDER(S) OR AUTHOR(S) BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#
#
# Makefile for the 'clk_mgr' sub-component of DAL.
# It provides the control and status of HW CLK_MGR pins.

CLK_MGR = clk_mgr.o

AMD_DAL_CLK_MGR = $(addprefix $(AMDDALPATH)/dc/clk_mgr/,$(CLK_MGR))

AMD_DISPLAY_FILES += $(AMD_DAL_CLK_MGR)


ifdef CONFIG_DRM_AMD_DC_SI
###############################################################################
# DCE 60
###############################################################################
CLK_MGR_DCE60 = dce60_clk_mgr.o

AMD_DAL_CLK_MGR_DCE60 = $(addprefix $(AMDDALPATH)/dc/clk_mgr/dce60/,$(CLK_MGR_DCE60))

AMD_DISPLAY_FILES += $(AMD_DAL_CLK_MGR_DCE60)
endif

###############################################################################
# DCE 100 and DCE8x
###############################################################################
CLK_MGR_DCE100 = dce_clk_mgr.o

AMD_DAL_CLK_MGR_DCE100 = $(addprefix $(AMDDALPATH)/dc/clk_mgr/dce100/,$(CLK_MGR_DCE100))

AMD_DISPLAY_FILES += $(AMD_DAL_CLK_MGR_DCE100)

###############################################################################
# DCE 100 and DCE8x
###############################################################################
CLK_MGR_DCE110 = dce110_clk_mgr.o

AMD_DAL_CLK_MGR_DCE110 = $(addprefix $(AMDDALPATH)/dc/clk_mgr/dce110/,$(CLK_MGR_DCE110))

AMD_DISPLAY_FILES += $(AMD_DAL_CLK_MGR_DCE110)
###############################################################################
# DCE 112
###############################################################################
CLK_MGR_DCE112 = dce112_clk_mgr.o

AMD_DAL_CLK_MGR_DCE112 = $(addprefix $(AMDDALPATH)/dc/clk_mgr/dce112/,$(CLK_MGR_DCE112))

AMD_DISPLAY_FILES += $(AMD_DAL_CLK_MGR_DCE112)
###############################################################################
# DCE 120
###############################################################################
CLK_MGR_DCE120 = dce120_clk_mgr.o

AMD_DAL_CLK_MGR_DCE120 = $(addprefix $(AMDDALPATH)/dc/clk_mgr/dce120/,$(CLK_MGR_DCE120))

AMD_DISPLAY_FILES += $(AMD_DAL_CLK_MGR_DCE120)
ifdef CONFIG_DRM_AMD_DC_DCN
###############################################################################
# DCN10
###############################################################################
CLK_MGR_DCN10 = rv1_clk_mgr.o rv1_clk_mgr_vbios_smu.o rv2_clk_mgr.o

AMD_DAL_CLK_MGR_DCN10 = $(addprefix $(AMDDALPATH)/dc/clk_mgr/dcn10/,$(CLK_MGR_DCN10))

AMD_DISPLAY_FILES += $(AMD_DAL_CLK_MGR_DCN10)

###############################################################################
# DCN20
###############################################################################
CLK_MGR_DCN20 = dcn20_clk_mgr.o

AMD_DAL_CLK_MGR_DCN20 = $(addprefix $(AMDDALPATH)/dc/clk_mgr/dcn20/,$(CLK_MGR_DCN20))

AMD_DISPLAY_FILES += $(AMD_DAL_CLK_MGR_DCN20)

###############################################################################
# DCN21
###############################################################################
CLK_MGR_DCN21 = rn_clk_mgr.o rn_clk_mgr_vbios_smu.o

# prevent build errors regarding soft-float vs hard-float FP ABI tags
# this code is currently unused on ppc64, as it applies to Renoir APUs only
ifdef CONFIG_PPC64
CFLAGS_$(AMDDALPATH)/dc/clk_mgr/dcn21/rn_clk_mgr.o := $(call cc-option,-mno-gnu-attribute)
endif

ifdef CONFIG_LOONGARCH
CFLAGS_REMOVE_$(AMDDALPATH)/dc/clk_mgr/dcn21/rn_clk_mgr.o := -msoft-float
endif

AMD_DAL_CLK_MGR_DCN21 = $(addprefix $(AMDDALPATH)/dc/clk_mgr/dcn21/,$(CLK_MGR_DCN21))

AMD_DISPLAY_FILES += $(AMD_DAL_CLK_MGR_DCN21)
endif
ifdef CONFIG_DRM_AMD_DC_DCN3_0
###############################################################################
# DCN30
###############################################################################
CLK_MGR_DCN30 = dcn30_clk_mgr.o dcn30_clk_mgr_smu_msg.o

# prevent build errors regarding soft-float vs hard-float FP ABI tags
# this code is currently unused on ppc64, as it applies to VanGogh APUs only
ifdef CONFIG_PPC64
CFLAGS_$(AMDDALPATH)/dc/clk_mgr/dcn30/dcn30_clk_mgr.o := $(call cc-option,-mno-gnu-attribute)
endif

# prevent build errors:
# ...: '-mgeneral-regs-only' is incompatible with the use of floating-point types
# this file is unused on arm64, just like on ppc64
ifdef CONFIG_ARM64
CFLAGS_REMOVE_$(AMDDALPATH)/dc/clk_mgr/dcn30/dcn30_clk_mgr.o := -mgeneral-regs-only
endif

ifdef CONFIG_LOONGARCH
CFLAGS_REMOVE_$(AMDDALPATH)/dc/clk_mgr/dcn30/dcn30_clk_mgr.o := -msoft-float
endif

AMD_DAL_CLK_MGR_DCN30 = $(addprefix $(AMDDALPATH)/dc/clk_mgr/dcn30/,$(CLK_MGR_DCN30))

AMD_DISPLAY_FILES += $(AMD_DAL_CLK_MGR_DCN30)
endif
