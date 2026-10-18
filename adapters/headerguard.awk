{ line[++n] = $0 }
END {
    blk = 0; inblk = 0
    for (i = 1; i <= n; i++) {
        L = line[i]
        if (L ~ /^[ \t\r]*$/) {
            inblk = 0
        } else if (L ~ /^HTTP\//) {
            blk++; inblk = 1
            stat[blk] = L
        } else if (inblk == 1) {
            p = index(L, ":")
            if (p > 0) {
                k = substr(L, 1, p - 1)
                v = substr(L, p + 1)
                gsub(/^[ \t]+/, "", k); gsub(/[ \t\r]+$/, "", k)
                gsub(/^[ \t]+/, "", v); gsub(/[ \t\r]+$/, "", v)
                gsub(/\r/, " ", v)
                gsub(/\t/, " ", v)
                lk = tolower(k)
                if (lk == "set-cookie") {
                    sc[blk, ++nsc[blk]] = v
                } else {
                    bk = blk SUBSEP k
                    if (!(bk in seen)) { seen[bk] = 1; ord[blk, ++kc[blk]] = k }
                    # NB: do NOT write this as
                    #     val[bk] = (bk in val) ? val[bk] " " v : v
                    # referencing val[bk] on the left-hand side CREATES the
                    # element, so the "in" test then always succeeds and every
                    # value is prefixed with a stray space.
                    if (bk in val) {
                        val[bk] = (val[bk] == "") ? v : val[bk] " " v
                    } else {
                        val[bk] = v
                    }
                }
            }
        }
    }
    if (blk == 0) exit 0
    last = blk
    code = stat[last]
    sub(/^HTTP\/[^ ]+[ ]+/, "", code)
    sub(/[ ].*$/, "", code)
    # printf, not print: print inserts OFS between every expression, which
    # would put a stray space around each field and break the tab split.
    printf "STATUS\t%s\n", code
    for (j = 1; j <= kc[last]; j++) {
        k = ord[last, j]
        printf "HDR\t%s\t%s\n", k, val[last SUBSEP k]
    }
    for (j = 1; j <= nsc[last]; j++) printf "COOKIE\t%s\n", sc[last, j]
}
