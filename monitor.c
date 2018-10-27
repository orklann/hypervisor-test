#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <Hypervisor/hv.h>
#include <Hypervisor/hv_error.h>
#include <Hypervisor/hv_vmx.h>

#define SEGM_SIZE 0xFFFF // size of real-mode segment

/* primary processor-based ctrl */
#define CTRL_HALT_INSTR (1<<7) // VM exit when guest executes halt instruction
#define CTRL_CR8_LOAD (1<<19)
#define CTRL_CR8_STORE (1<<20)
#define CTRL_SECOND (1<<31) // enable secondary processor controls
#define PRI_DEF1 (0x401E172) // default1's for primary
#define PROC1_BITMAP (PRI_DEF1 | CTRL_HALT_INSTR | CTRL_UNCON_IO | CTRL_SECOND | CTRL_CR8_LOAD | CTRL_CR8_STORE)

/* secondary processor-based ctrl */
#define CTRL_UNRSTR (1<<7) // To execute real-mode code
#define PROC2_BITMAP CTRL_UNRSTR

/* pin-based ctrl */
#define CTRL_UNCON_IO (1<<24) // VM exit when guest executes IO instruction
#define PIN_DEF1 (0x16)
#define PIN_BITMAP (PIN_DEF1 | 0x1)

/* map guest physical address to host virtual address */
#define VM_MEM_MAP(uva, gpa, size, flags) \
    if ( (ret = hv_vm_map(uva, gpa, size, flags) != HV_SUCCESS)) { \
    print_err(ret); \
    exit(0); \
    }

uint64_t
rreg(hv_vcpuid_t vcpu, hv_x86_reg_t reg)
{
	uint64_t v;

	if (hv_vcpu_read_register(vcpu, reg, &v)) {
		abort();
	}

	return v;
}

 /* write GPR */
void
wreg(hv_vcpuid_t vcpu, hv_x86_reg_t reg, uint64_t v)
{
	if (hv_vcpu_write_register(vcpu, reg, v)) {
		abort();
	}
}

#define RAX ((uint16_t)rreg(vcpu, HV_X86_RAX))
#define RBX ((uint16_t)rreg(vcpu, HV_X86_RBX))
#define RIP ((uint16_t)rreg(vcpu, HV_X86_RIP))
#define SET_AX(v) wreg(vcpu, HV_X86_RAX, v)

/* execute vm represented by vcpu */
#define HV_EXEC(vcpu) \
    if ( (ret = hv_vcpu_run(*vcpu)) != HV_SUCCESS) { \
    print_err(ret); \
    exit(0); \
    }

static void print_err(hv_return_t err){
    switch (err) {
    case HV_ERROR:
        printf("Error: HV_ERROR\n");
        break;
    case HV_BUSY:
        printf("Error: HV_BUSY\n");
        break;
    case HV_BAD_ARGUMENT:
        printf("Error: HV_BAD_ARGUMENT\n");
        break;
    case HV_NO_RESOURCES:
        printf("Error: HV_NO_RESOURCES\n");
        break;
    case HV_NO_DEVICE:
        printf("Error: HV_NO_DEVICE\n");
        break;
    case HV_UNSUPPORTED:
        printf("Error: HV_UNSUPPORTED\n");
        break;
    default:
        printf("Unknown Error\n");
    }
}

static void write_vmcs(hv_vcpuid_t *vcpu, uint32_t field, uint64_t value) {
    hv_return_t ret;

    if ( (ret = hv_vmx_vcpu_write_vmcs(*vcpu, field, value)) != HV_SUCCESS) {
    print_err(ret);
    exit(0);
    }
}

static void read_vmcs(hv_vcpuid_t *vcpu, uint32_t field, uint64_t *value) {
    hv_return_t ret;

    if ( (ret = hv_vmx_vcpu_read_vmcs(*vcpu, field, value)) != HV_SUCCESS) {
    print_err(ret);
    exit(0);
    }
}

static void read_caps(hv_vmx_capability_t field, uint64_t *value)
{
    hv_return_t ret;

    if ( (ret = hv_vmx_read_capability(field, value)) != HV_SUCCESS) {
    print_err(ret);
    exit(0);
    }
}

static void vmcs_init_ctrl(hv_vcpuid_t *vcpu)
{
    uint64_t cap;

    /* set default1 bits and some capabilities */

    read_caps(HV_VMX_CAP_PINBASED, &cap);
    write_vmcs(vcpu, VMCS_CTRL_PIN_BASED, PIN_BITMAP | ((cap & 0xffffffff) & (cap >> 32)));

    read_caps(HV_VMX_CAP_PROCBASED, &cap);
    write_vmcs(vcpu, VMCS_CTRL_CPU_BASED, (PROC1_BITMAP | (cap & 0xffffffff)) & (cap >> 32));

    read_caps(HV_VMX_CAP_PROCBASED2, &cap);
    write_vmcs(vcpu, VMCS_CTRL_CPU_BASED2, (PROC2_BITMAP | (cap & 0xffffffff)) & (cap >> 32));

    read_caps(HV_VMX_CAP_ENTRY, &cap);
    write_vmcs(vcpu, VMCS_CTRL_VMENTRY_CONTROLS, (0x11ff | (cap & 0xffffffff)) & (cap >> 32));

    read_caps(HV_VMX_CAP_EXIT, &cap);
    write_vmcs(vcpu, VMCS_CTRL_VMEXIT_CONTROLS, (0x36dff | (cap & 0xffffffff)) & (cap >> 32));
}

static void vmcs_init_guest(hv_vcpuid_t *vcpu)
{
    write_vmcs(vcpu, VMCS_GUEST_RIP, 0x100); // load program segment at segment:offset -> 0x0:0x100
    write_vmcs(vcpu, VMCS_GUEST_RSP, SEGM_SIZE); // stack pointer at segment:offset -> 0x0:0xffff
    write_vmcs(vcpu, VMCS_GUEST_RFLAGS, 0x2);

    write_vmcs(vcpu, VMCS_GUEST_IA32_DEBUGCTL, 0x0);
    write_vmcs(vcpu, VMCS_GUEST_IA32_EFER, 0);
    write_vmcs(vcpu, VMCS_GUEST_TR, 0);
    write_vmcs(vcpu, VMCS_GUEST_TR_BASE, 0);
    write_vmcs(vcpu, VMCS_GUEST_TR_LIMIT, SEGM_SIZE);
    write_vmcs(vcpu, VMCS_GUEST_TR_AR, 0x83);
    write_vmcs(vcpu, VMCS_GUEST_CS, 0x0);
    write_vmcs(vcpu, VMCS_GUEST_CS_BASE, 0x0);
    write_vmcs(vcpu, VMCS_GUEST_CS_LIMIT, SEGM_SIZE);
    write_vmcs(vcpu, VMCS_GUEST_CS_AR, 0x9b);
    write_vmcs(vcpu, VMCS_GUEST_DS, 0);
    write_vmcs(vcpu, VMCS_GUEST_DS_BASE, 0);
    write_vmcs(vcpu, VMCS_GUEST_DS_LIMIT, SEGM_SIZE);
    write_vmcs(vcpu, VMCS_GUEST_DS_AR, 0x93);
    write_vmcs(vcpu, VMCS_GUEST_ES, 0);
    write_vmcs(vcpu, VMCS_GUEST_ES_BASE, 0);
    write_vmcs(vcpu, VMCS_GUEST_ES_LIMIT, SEGM_SIZE);
    write_vmcs(vcpu, VMCS_GUEST_ES_AR, 0x93);
    write_vmcs(vcpu, VMCS_GUEST_FS, 0);
    write_vmcs(vcpu, VMCS_GUEST_FS_BASE, 0);
    write_vmcs(vcpu, VMCS_GUEST_FS_LIMIT, SEGM_SIZE);
    write_vmcs(vcpu, VMCS_GUEST_FS_AR, 0x93);
    write_vmcs(vcpu, VMCS_GUEST_GS, 0);
    write_vmcs(vcpu, VMCS_GUEST_GS_BASE, 0);
    write_vmcs(vcpu, VMCS_GUEST_GS_LIMIT, SEGM_SIZE);
    write_vmcs(vcpu, VMCS_GUEST_GS_AR, 0x93);
    write_vmcs(vcpu, VMCS_GUEST_SS, 0);
    write_vmcs(vcpu, VMCS_GUEST_SS_BASE, 0);
    write_vmcs(vcpu, VMCS_GUEST_SS_LIMIT, SEGM_SIZE);
    write_vmcs(vcpu, VMCS_GUEST_SS_AR, 0x93);
    write_vmcs(vcpu, VMCS_GUEST_LDTR, 0);
    write_vmcs(vcpu, VMCS_GUEST_LDTR_BASE, 0);
    write_vmcs(vcpu, VMCS_GUEST_LDTR_LIMIT, SEGM_SIZE);
    write_vmcs(vcpu, VMCS_GUEST_LDTR_AR, 0x82);
    write_vmcs(vcpu, VMCS_GUEST_GDTR_BASE, 0);
    write_vmcs(vcpu, VMCS_GUEST_GDTR_LIMIT, SEGM_SIZE);
    write_vmcs(vcpu, VMCS_GUEST_IDTR_BASE, 0);
    write_vmcs(vcpu, VMCS_GUEST_IDTR_LIMIT, SEGM_SIZE);

    write_vmcs(vcpu, VMCS_GUEST_CR0, 0x20); // in particular, PE and PG disabled; execute in real-mode
    write_vmcs(vcpu, VMCS_GUEST_CR3, 0x0);
    write_vmcs(vcpu, VMCS_GUEST_DR7, 0x0);
    write_vmcs(vcpu, VMCS_GUEST_CR4, 1L<<13);

    write_vmcs(vcpu, VMCS_CTRL_EXC_BITMAP, 0xffffffff);
    write_vmcs(vcpu, VMCS_CTRL_CR0_MASK, 0x60000000);
    write_vmcs(vcpu, VMCS_CTRL_CR0_SHADOW, 0x0);
    write_vmcs(vcpu, VMCS_CTRL_CR4_MASK, 0x0);
    write_vmcs(vcpu, VMCS_CTRL_CR4_SHADOW, 0x0);
}

int main(int argc, char *argv[]){

    // shellcode to modify BX register
    unsigned char *shellcode = "\x66\xbb\x64\x00";
    hv_return_t ret;
    /* Create the VM */
    if ( (ret = hv_vm_create(HV_VM_DEFAULT)) != HV_SUCCESS) {
        print_err(ret);
        exit(0);
    }

    /* Create Virtual CPU. Can now manipulate vmcs. */
    hv_vcpuid_t vcpu;
    if ( (ret = hv_vcpu_create(&vcpu, HV_VCPU_DEFAULT)) != HV_SUCCESS) {
        print_err(ret);
        exit(0);
    }

    /* Set the vmcs guest area */
    vmcs_init_guest(&vcpu);

    /* Set the vmcs control area */
    vmcs_init_ctrl(&vcpu);

    /* Allocate page-aligned memory and map to guest address space at 0x0 */
    #define VM_MEM_SIZE (1 * 1024 * 1024)
    static unsigned char *mem_map;
    if (!(mem_map = valloc(VM_MEM_SIZE))) {
     abort();
    }
    posix_memalign((void **)&mem_map, 4096, SEGM_SIZE); // memory must be aligned to page boundary

    memcpy((unsigned char*)mem_map, (unsigned char*)shellcode, 4);

    VM_MEM_MAP(mem_map, 0, SEGM_SIZE, HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC);
    hv_vcpu_flush(vcpu);
    wreg(vcpu, HV_X86_RIP, 0x000);
    /* Main loop: execute guest until VM exit */
    uint64_t exit_reas, err;
    int stop = 0;
    int n = 0;
    while (!stop) {
        HV_EXEC(&vcpu);
        read_vmcs(&vcpu, VMCS_RO_EXIT_REASON, &exit_reas);
        uint16_t rbx = RBX;
        printf("RBX = %lu\n", rbx);
        uint16_t rip = RIP;
        printf("RIP = %lu\n", rip);
        n++;
        if (n >= 10) stop = 1;
        switch (exit_reas) {
        case VMX_REASON_HLT:
            printf("HLT\n");
            stop = 1;
            break;
        case VMX_REASON_IRQ:
            printf("INTERRUPT\n");
            break;
        case VMX_REASON_EPT_VIOLATION:
        ;
        default:
        ;
        }
    }
}
