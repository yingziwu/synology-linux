
class Platform
    module Helper

        def aarch64?
            @family == :armv8
        end

        def virtual?
            @target == :KVMX64
        end

        def numa?
            @target == :PURLEY || @target == :EPYC7002
        end
    end
end
