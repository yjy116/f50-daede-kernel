These are unedited `pahole -F btf -C sk_buff` and final-module `objdump`
outputs from both jobs of build run
https://github.com/yjy116/f50-daede-kernel/actions/runs/36713314939
(commit `2ee5ab8584d18e415df9c5f48a6c83aeabcf8676`).

Both layouts repeat `ip_summed` through the anonymous union's promoted struct
and its named `headers` alias. Both printed offsets are already absolute:
byte 128, bits 5–6. The matching raw BTF independently resolves that location
by accumulating only anonymous-member offsets. The build artifact gate
checks both representations and rejects disagreements; fixtures only exercise
the parser and are not substitutes for real compiled artifacts.
