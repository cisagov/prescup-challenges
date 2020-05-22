# President's Cup Cybersecurity Competition 2019 Challenges
#
# Copyright 2020 Carnegie Mellon University.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
# INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
# UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR
# IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF
# FITNESS FOR PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS
# OBTAINED FROM USE OF THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT
# MAKE ANY WARRANTY OF ANY KIND WITH RESPECT TO FREEDOM FROM PATENT,
# TRADEMARK, OR COPYRIGHT INFRINGEMENT.
#
# Released under a MIT (SEI)-style license, please see license.txt or
# contact permission@sei.cmu.edu for full terms.
#
# [DISTRIBUTION STATEMENT A] This material has been approved for public
# release and unlimited distribution.  Please see Copyright notice for
# non-US Government use and distribution.
#
# DM20-0347

curl https://raw.githubusercontent.com/torvalds/linux/ea136a112d89bade596314a1ae49f748902f4727/arch/x86/kernel/apic/apic.c | sed 1,1354d | sed 42,47d | sed 51d | sed 54,56d | sed 73,83d | sed 102,274d | sed 128d | sed 133,1233d  > file1.c

if [[ $(man -P cat sed | head -n 2 | grep '\S') == *"BSD"* ]]; then
    sed -i '' "s/apic_intr_mode_init/func1/g" file1.c
    sed -i '' "s/apic_intr_mode_select/func2/g" file1.c
    sed -i '' "s/apic_bsp_setup/func3/g" file1.c
    sed -i '' "s/lapic_setup_esr/func4/g" file1.c
    sed -i '' "s/lapic_is_integrated/func5/g" file1.c
    sed -i '' "s/\/\* Due to the Pentium erratum 3AP. \*\///g" file1.c
    sed -i '' "s/apic_write/func6/g" file1.c
    sed -i '' "s/apic_read/func9/g" file1.c
    sed -i '' "s/apic_pending_intr_clear/func7/g" file1.c
    sed -i '' "s/boot_cpu_has/func8/g" file1.c
    sed -i '' "73i\\
    \\
    " file1.c
    sed -i '' "s/max_loops = (lo.*/max_loops = cpu_khz << 10 - (ntsc - tsc);/g" file1.c
    sed -i '' 94d file1.c
    sed -i '' "s/apic_ap_setup/func10/g" file1.c
    sed -i '' "s/__x2apic_disable/func11/g" file1.c
    sed -i '' "s/!func8/!func12/g" file1.c
else
    sed -i'' "s/apic_intr_mode_init/func1/g" file1.c
    sed -i'' "s/apic_intr_mode_select/func2/g" file1.c
    sed -i'' "s/apic_bsp_setup/func3/g" file1.c
    sed -i'' "s/lapic_setup_esr/func4/g" file1.c
    sed -i'' "s/lapic_is_integrated/func5/g" file1.c
    sed -i'' "s/\/\* Due to the Pentium erratum 3AP. \*\///g" file1.c
    sed -i'' "s/apic_write/func6/g" file1.c
    sed -i'' "s/apic_read/func9/g" file1.c
    sed -i'' "s/apic_pending_intr_clear/func7/g" file1.c
    sed -i'' "s/boot_cpu_has/func8/g" file1.c
    sed -i'' "73i\\
    " file1.c
    sed -i'' "s/max_loops = (lo.*/max_loops = cpu_khz << 10 - (ntsc - tsc);/g" file1.c
    sed -i'' 94d file1.c
    sed -i'' "s/apic_ap_setup/func10/g" file1.c
    sed -i'' "s/__x2apic_disable/func11/g" file1.c
    sed -i'' "s/!func8/!func12/g" file1.c
fi

curl https://raw.githubusercontent.com/torvalds/linux/28e9091e3119933c38933cb8fc48d5618eb784c8/drivers/infiniband/hw/mlx5/cq.c | sed 1,1133d | sed 74,324d | sed 47,50d > file2.c

curl https://raw.githubusercontent.com/torvalds/linux/28e9091e3119933c38933cb8fc48d5618eb784c8/drivers/infiniband/hw/mlx5/cq.c | sed 1,38d | sed 29,32d | sed 127,1414d >> file2.c

if [[ $(man -P cat sed | head -n 2 | grep '\S') == *"BSD"* ]]; then
    sed -i '' "s/mlx5_ib_cq_clean/func1/g" file2.c
        sed -i '' "s/mlx5_ib_modify_cq/func2/g" file2.c
    sed -i '' "s/mlx5_core_modify_cq_moderation/func3/g" file2.c
    sed -i '' "s/resize_user/func4/g" file2.c
    sed -i '' "s/(size_t)ucmd.cqe_size/ucmd.cqe_size/g" file2.c
    sed -i '' "s/mlx5_ib_cont_pages/func5/g" file2.c
    sed -i '' "s/mlx5_ib_cq_comp(struct mlx5_core_cq \*cq)/func6(struct mlx5_core_cq \*cq, struct mlx5_eqe \*eqe)/g" file2.c
    sed -i '' "s/mlx5_ib_cq_event/func7/g" file2.c
    sed -i '' "s/get_cqe_from_buf(\&cq->buf, n, cq->mcq.cqe_sz)/mlx5_frag_buf_get_wqe(\&cq->buf.fbc, n)/g" file2.c
    sed -i '' "s/get_cqe/func8/g" file2.c
    sed -i '' "s/sw_ownership_bit/func9/g" file2.c
    sed -i '' "s/get_sw_cqe/func10/g" file2.c
    sed -i '' "s/(cqe64->op_own) >> 4/func8_opcode(cqe64)/g" file2.c
    sed -i '' "s/next_cqe_sw/func11/g" file2.c
    sed -i '' "s/get_umr_comp/func12/g" file2.c
    sed -i '' "s/handle_good_req/func13/g" file2.c
else
    sed -i'' "s/mlx5_ib_cq_clean/func1/g" file2.c
        sed -i'' "s/mlx5_ib_modify_cq/func2/g" file2.c
        sed -i'' "s/mlx5_core_modify_cq_moderation/func3/g" file2.c
        sed -i'' "s/resize_user/func4/g" file2.c
        sed -i'' "s/(size_t)ucmd.cqe_size/ucmd.cqe_size/g" file2.c
        sed -i'' "s/mlx5_ib_cont_pages/func5/g" file2.c
        sed -i'' "s/mlx5_ib_cq_comp(struct mlx5_core_cq \*cq)/func6(struct mlx5_core_cq \*cq, struct mlx5_eqe \*eqe)/g" file2.c
        sed -i'' "s/mlx5_ib_cq_event/func7/g" file2.c
        sed -i'' "s/get_cqe_from_buf(\&cq->buf, n, cq->mcq.cqe_sz)/mlx5_frag_buf_get_wqe(\&cq->buf.fbc, n)/g" file2.c
        sed -i'' "s/get_cqe/func8/g" file2.c
        sed -i'' "s/sw_ownership_bit/func9/g" file2.c
        sed -i'' "s/get_sw_cqe/func10/g" file2.c
        sed -i'' "s/(cqe64->op_own) >> 4/func8_opcode(cqe64)/g" file2.c
        sed -i'' "s/next_cqe_sw/func11/g" file2.c
        sed -i'' "s/get_umr_comp/func12/g" file2.c
        sed -i'' "s/handle_good_req/func13/g" file2.c
fi
