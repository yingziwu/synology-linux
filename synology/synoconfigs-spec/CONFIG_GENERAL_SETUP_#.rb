
require 'syno_kconfig'

describe 'General setup' do
    include SynoKconfig

    #
    # built-in configs for all platforms
    #
    %w[
	CONFIG_SWAP
	CONFIG_SYSVIPC
	CONFIG_SYSVIPC_SYSCTL
	CONFIG_POSIX_MQUEUE
	CONFIG_POSIX_MQUEUE_SYSCTL
	CONFIG_USELIB
	CONFIG_AUDIT

	CONFIG_PREEMPT_NONE

	CONFIG_TASKSTATS
	CONFIG_TASK_DELAY_ACCT
	CONFIG_TASK_XACCT
	CONFIG_TASK_IO_ACCOUNTING
	CONFIG_PSI

	CONFIG_VM_EVENT_COUNTERS
	CONFIG_SLUB_DEBUG
	CONFIG_SLUB

	CONFIG_TRACEPOINTS

	CONFIG_RD_LZMA

	CONFIG_DEBUG_INFO
	CONFIG_DEBUG_INFO_BTF

	CONFIG_SCHED_DEBUG
    ].each do |cfg|
        it "#{cfg}=y" do
            platforms.verify(cfg, builtin?)
        end
    end

    #
    # disabled configs for all platforms
    #
    %w[
	CONFIG_PREEMPT_VOLUNTARY
	CONFIG_PREEMPT

	CONFIG_PSI_DEFAULT_DISABLED
    ].each do |cfg|
        it "#{cfg} is not set" do
            platforms.verify(cfg, disabled?)
        end
    end
end

