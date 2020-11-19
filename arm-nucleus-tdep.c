/* ARM Nucleus target support.

   Copyright (C) 2014-2015 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include "defs.h"
#include "osabi.h"
#include "arm-tdep.h"
#include "arch/arm-get-next-pcs.h"
#include "gdbcore.h"
#include "value.h"
#include "frame-unwind.h"
#include "trad-frame.h"
#include "target-descriptions.h"
#include "nucleus-tdep.h"

/* EXC_RETURN values for Cortex-M3.  */
#define EXC_RETURN_HANDLER_MSP 0xfffffff1
#define EXC_RETURN_THREAD_MSP 0xfffffff9
#define EXC_RETURN_THREAD_PSP 0xfffffffd

/* ISR Handlers in Nucleus for different ARM architectures.  */
static const char nu_arm_swi_handler[] = "ESAL_AR_ISR_SWI_Except_Handler";
static const char nu_arm_svc_handler[] = "ESAL_AR_ISR_SVC_Handler";

struct arm_nucleus_cache
{
  /* Base address.  */
  CORE_ADDR base;
  CORE_ADDR prev_pc;
  CORE_ADDR prev_lr;
  CORE_ADDR prev_sp;

  /* Saved registers.  */
  struct trad_frame_saved_reg *saved_regs;
};

/* Initialize register cache.  */

static struct arm_nucleus_cache *
nucleus_init_cache (struct frame_info *this_frame)
{
  struct arm_nucleus_cache *cache;

  cache = FRAME_OBSTACK_ZALLOC (struct arm_nucleus_cache);

  cache->prev_sp = 0;
  cache->prev_pc = 0;
  cache->prev_lr = 0;

  /* Saved registers.  */
  cache->saved_regs = trad_frame_alloc_saved_regs (this_frame);

  return cache;
}

/* Make register cache for trampoline return frame.  */

static struct arm_nucleus_cache *
arm_nucleus_make_tramp_cache (struct frame_info *this_frame,
			      void **this_nucleus_cache)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  struct arm_nucleus_cache *cache;

  if (*this_nucleus_cache)
    return (arm_nucleus_cache*)*this_nucleus_cache;

  cache = nucleus_init_cache (this_frame);
  (*this_nucleus_cache) = cache;

  cache->prev_sp = get_frame_sp (this_frame);

  return cache;
}

/* Frame ID builder for trampolinereturn frame.  */

static void
arm_nucleus_tramp_id (struct frame_info *this_frame,
		      void **this_cache,
		      struct frame_id *this_id)
{
  struct arm_nucleus_cache *cache =
    arm_nucleus_make_tramp_cache (this_frame, this_cache);

  *this_id = frame_id_build (cache->prev_sp, get_frame_pc (this_frame));
}

/* Obtain previous register for trampoline return frame.  */

static struct value *
arm_nucleus_tramp_prev_register (struct frame_info *this_frame,
				 void **this_cache,
				 int prev_regnum)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  enum bfd_endian byte_order_for_code = gdbarch_byte_order_for_code (gdbarch);
  struct arm_nucleus_cache *cache;
  CORE_ADDR lr, pc_addr, user_rtrn_addr = 0;

  cache = arm_nucleus_make_tramp_cache (this_frame, this_cache);

  /* The value was already reconstructed into PREV_SP.  */
  if (prev_regnum == gdbarch_sp_regnum (gdbarch) && cache->prev_sp)
    return frame_unwind_got_constant (this_frame, prev_regnum,
                                      cache->prev_sp);

  if (prev_regnum == ARM_PC_REGNUM)
    {
      if (read_nucleus_register (this_frame, "nu_user_rtrn_addr",
				 &user_rtrn_addr) == -1)
	{
	  user_rtrn_addr =
	    parse_and_eval_address ("((TC_TCB *)TCD_Current_Thread)->tc_return_addr");
	}

      cache->prev_pc = user_rtrn_addr;

      if (cache->prev_pc == 0)
	{
	  /* Special handling of bx lr instruction after poping lr from stack.  */
	  if (read_memory_unsigned_integer (get_frame_pc (this_frame),
					    4, byte_order_for_code)
	      == 0xe12fff1e)
	    cache->prev_pc = get_frame_register_unsigned (this_frame,
							  ARM_LR_REGNUM);
	  else
	    {
	      /* We are in PROC_AR_User_Mode and mode flag has been cleared.
		 Get previous PC relative to sp.  */
	      pc_addr = get_frame_register_unsigned (this_frame, ARM_SP_REGNUM) + 12;
	      cache->prev_pc = get_frame_memory_unsigned (this_frame, pc_addr, 4);
	    }
	}

      return frame_unwind_got_constant (this_frame, prev_regnum,
					cache->prev_pc);
    }

  /* With current Nucleus implementation there is no way to
     get previous frame's LR from trampoline return frame.  If
     ever we need LR, simply return 0.  Returning THIS_FRAME's
     LR as previous frame's LR can cause cyclic unwinding.  */
  if (prev_regnum == ARM_LR_REGNUM)
    return frame_unwind_got_constant (this_frame, prev_regnum, 0);

  return trad_frame_get_prev_register (this_frame, cache->saved_regs,
                                       prev_regnum);
}

/* Frame unwinder for trampoline return frame.  */
struct frame_unwind arm_nucleus_tramp_return_unwind =
{
  SIGTRAMP_FRAME,
  nu_tramp_frame_unwind_stop_reason,
  arm_nucleus_tramp_id,
  arm_nucleus_tramp_prev_register,
  NULL,
  nucleus_tramp_unwind_sniffer
};

/* Make register cache for SWI handler frame.  */

static struct arm_nucleus_cache *
arm_nucleus_make_exc_cache (struct frame_info *this_frame,
			    void **this_nucleus_cache)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  struct arm_nucleus_cache *cache;

  if (*this_nucleus_cache)
    return (arm_nucleus_cache*)*this_nucleus_cache;

  cache = nucleus_init_cache (this_frame);
  (*this_nucleus_cache) = cache;

  cache->prev_sp = get_frame_register_unsigned (this_frame,
                                                ARM_SP_REGNUM);

  cache->prev_lr = get_frame_register_unsigned (this_frame,
                                                ARM_IP_REGNUM);

  return cache;
}

/* Obtain previous frame's register for SWI handler frame.  */

static struct value *
arm_nucleus_exc_prev_register (struct frame_info *this_frame,
			       void **this_cache,
			       int prev_regnum)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  CORE_ADDR pc_addr, stack_start_addr, swi_start_addr;

  struct arm_nucleus_cache *cache = arm_nucleus_make_exc_cache (this_frame,
								this_cache);

  /* The value was already reconstructed into PREV_SP.  */
  if (prev_regnum == ARM_SP_REGNUM && cache->prev_sp)
    return frame_unwind_got_constant (this_frame, prev_regnum,
                                      cache->prev_sp);

  if (prev_regnum == ARM_PC_REGNUM)
    {
      stack_start_addr = get_minsym_address ("ESAL_AR_ISR_SUP_Stack");
      swi_start_addr = get_minsym_address (nu_arm_swi_handler);

      pc_addr = get_frame_register_unsigned (this_frame,
					     ARM_PC_REGNUM);

      /* If context is not saved yet and nothing has been pushed on stack yet,
     get previous frame's PC and LR from LR and R12.  */
      if (pc_addr == swi_start_addr)
	cache->prev_pc = get_frame_register_unsigned (this_frame,
						      ARM_LR_REGNUM);
      else
	{
	  /* If we are not at first instruction, get previous PC from stack.  LR is
	     pushed on to supervisor stack first.  So we need to get first element
	     of supervisor stack.  Below is definition of supervisor stack in Nucleus
	     code:

	     static UINT8 ESAL_AR_ISR_SUP_Stack[ESAL_GE_CPU_COUNT][ESAL_AR_ISR_SUP_STACK_SIZE];

	     ESAL_GE_CPU_COUNT: Configurable macro for CPU count
	     ESAL_AR_ISR_SUP_STACK_SIZE: Configurable macro for Size of stack.

	     We need to get first element pushed on to stack.  For falling
	     stack it will be

	     ESAL_AR_ISR_SUP_Stack[ESAL_GE_CPU_COUNT][ESAL_AR_ISR_SUP_STACK_SIZE-1]

	     But we don't know what is CPU count and also what is stack size.
	     Also in Nucleus stack, elements are pushed on aligned addresses.
	     And address alignment is also configurable depending upon size
	     of data pointer.  */

	  CORE_ADDR size_of_stack = 0, current_cpu_id = 0;
	  CORE_ADDR stack_end_addr;
	  int stack_alignment_mask = ~((gdbarch_dwarf2_addr_size (gdbarch) * 2)-1);

	  /* Try to obtain supervisor stack size using its specific Nucleus register.
	     Fall back to expression evaluation in case of failure.  */
	  if (read_nucleus_register (this_frame, "nu_sup_stk_size", &size_of_stack) == -1)
	    size_of_stack = parse_and_eval_address ("sizeof (ESAL_AR_ISR_SUP_Stack[0])");

	  /* Obtain CPU ID from Nucleus register.  Set to zero in case failure.
	     This needs some improvement as Nucleus specific registers are only
	     available for NDA and MITMA.  */
	  if (read_nucleus_register (this_frame, "nu_cur_cpu_id", &current_cpu_id) == -1)
	    current_cpu_id = 0;

	  /* Get address of ESAL_AR_ISR_SUP_Stack[current_cpu_id][size_of_stack - 1]  */
	  stack_end_addr = stack_start_addr + (current_cpu_id*size_of_stack) + size_of_stack - 1;

	  /* Get aligned address.  */
	  stack_end_addr = stack_end_addr & stack_alignment_mask;

	  pc_addr = stack_end_addr - 4;

	  cache->prev_pc = get_frame_memory_unsigned (this_frame, pc_addr, 4);
	}

      return frame_unwind_got_constant (this_frame, prev_regnum,
					cache->prev_pc);
    }

  if (prev_regnum == ARM_LR_REGNUM && cache->prev_lr)
    return frame_unwind_got_constant (this_frame, prev_regnum,
                                      cache->prev_lr);

  return trad_frame_get_prev_register (this_frame, cache->saved_regs,
                                       prev_regnum);
}

/* Construct frame ID of SWI handler frame.  */

static void
arm_nucleus_exc_handler_id (struct frame_info *this_frame,
			    void **this_cache,
			    struct frame_id *this_id)
{
  struct arm_nucleus_cache *cache =
    arm_nucleus_make_exc_cache (this_frame, this_cache);

  *this_id = frame_id_build (cache->prev_sp, get_frame_pc (this_frame));
}

/* Sniffer for SWI handler frame.  */

static int
arm_nucleus_exc_handler_sniffer (const struct frame_unwind *self,
				 struct frame_info *this_frame,
				 void **this_prologue_cache)
{
  CORE_ADDR pc = get_frame_pc (this_frame);
  struct minimal_symbol *indsym;

  const char *symname;

  if (pc ==0)
    return 0;

  indsym = lookup_minimal_symbol_by_pc (pc).minsym;
  if (indsym == NULL)
    return 0;

  symname = MSYMBOL_LINKAGE_NAME (indsym);
  /* Make sure we are in exception handler code.  */
  if (symname == NULL
      || !startswith (symname, nu_arm_swi_handler))
    return 0;

  return 1;
}

/* Frame unwinder for SWI exception handler frame unwinding.  */
struct frame_unwind arm_nucleus_exception_handler_unwind =
{
  NORMAL_FRAME,
  default_frame_unwind_stop_reason,
  arm_nucleus_exc_handler_id,
  arm_nucleus_exc_prev_register,
  NULL,
  arm_nucleus_exc_handler_sniffer
};

/* Skip ARM vector table for svc and move to SWI exception handler.  */

static CORE_ADDR
nucleus_syscall_next_pc (struct arm_get_next_pcs *self)
{
  CORE_ADDR next_pc = get_minsym_address (nu_arm_swi_handler);
  if (next_pc == (CORE_ADDR)-1)
    next_pc = get_minsym_address (nu_arm_svc_handler);

  return next_pc;
}

/* Check if symbol is ISR handler.  */

static int
symbol_is_isr_handler (const char *symname)
{
  if (symname)
    {
      if (startswith (symname, nu_arm_swi_handler)
	  || startswith (symname, nu_arm_svc_handler))
	return 1;
    }

  return 0;
}

static CORE_ADDR
nuproc_skip_solib_resolver (struct gdbarch *gdbarch, CORE_ADDR pc)
{
  struct minimal_symbol *msym;
  const char *symname;
  CORE_ADDR swi_start_addr, caller_pc;

  msym = lookup_minimal_symbol_by_pc (pc).minsym;
  if (msym == NULL)
    return 0;

  symname = MSYMBOL_LINKAGE_NAME (msym);

  /* Check if execution is in the ISR exception handler and it is coming via a
     trampoline path.  If thats the case, return __nutramp frame's PC.  */
  if (symbol_is_isr_handler (symname))
    {
      caller_pc = frame_unwind_caller_pc (get_current_frame ());
      msym = lookup_minimal_symbol_by_pc (caller_pc).minsym;

      /* Check if the previous frame is at EXC_RETURN.  According to "ARMv7-M
	 Architecture Reference Manual, the exception frame returns to one of
	 these addresses.  If previous frame is at EXC_RETURN, unwind it to
	 reach __nutramp frame.  */
      if (gdbarch_tdep (gdbarch)->is_m
	  && (caller_pc == EXC_RETURN_HANDLER_MSP || caller_pc == EXC_RETURN_THREAD_MSP
	      || caller_pc == EXC_RETURN_THREAD_PSP))
	{
	  caller_pc = frame_unwind_caller_pc (get_prev_frame (get_current_frame ()));
	  msym = lookup_minimal_symbol_by_pc (caller_pc).minsym;
	}

      if (msym == NULL)
	return 0;

      symname = MSYMBOL_LINKAGE_NAME (msym);
      if (startswith (symname, "__nutramp_"))
	return caller_pc;
    }

  return 0;
}

/* Initialize ARM-specific Nucleus settings.  */

static void
arm_nucleus_init_abi (struct gdbarch_info info,
		      struct gdbarch *gdbarch)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);
  const struct target_desc *tdesc = info.target_desc;

  /* Set solib options.  */
  nucleus_init_abi (info, gdbarch, ARM_NUM_REGS);
  frame_unwind_append_unwinder (gdbarch, &arm_nucleus_tramp_return_unwind);
  frame_unwind_append_unwinder (gdbarch, &arm_nucleus_exception_handler_unwind);
  tdep->arm_get_next_pcs_ops->syscall_next_pc = nucleus_syscall_next_pc;
  set_gdbarch_skip_solib_resolver (gdbarch, nuproc_skip_solib_resolver);

  /* Do not register software single stepping handler in the case of NDA as
     NDA is capable of doing hardware single stepping.  */
  if (tdesc == NULL 
      || tdesc_find_feature (tdesc,"org.gnu.gdb.arm.nucleus.nda") == NULL)
    {
      set_gdbarch_software_single_step (gdbarch, arm_software_single_step);
    }
}

/* -Wmissing-prototypes */
extern initialize_file_ftype _initialize_arm_nucleus_tdep;

void
_initialize_arm_nucleus_tdep (void)
{
  gdbarch_register_osabi_sniffer (bfd_arch_arm,
				  bfd_target_elf_flavour,
				  nucleus_osabi_sniffer);

  gdbarch_register_osabi (bfd_arch_arm, 0, GDB_OSABI_NUCLEUS,
			  arm_nucleus_init_abi);
}
