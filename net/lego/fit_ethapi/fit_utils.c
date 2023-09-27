#include <net/lwip/pbuf.h>
#include "fit_log.h"

#include "fit_utils.h"

/**
 * Cut the pbuf chain into two half at offset.
 * 
 * @return struct pbuf* The head of the second half
 */
int utils_pbuf_cut(struct pbuf *p, off_t off, 
    struct pbuf **p1, struct pbuf **p2)
{
    struct pbuf *cut, *head1, *head2;
    size_t len1, len2;
    int ret;

    if (off > p->tot_len) {
        fit_warn("Trying to cut a pbuf(len=%d) at %lu\n", 
            p->tot_len, off);
        ret = -EINVAL;
        goto err;
    } else if (off == 0) {
        *p1 = NULL;
        *p2 = p;
        return 0;
    } else if (off == p->tot_len) {
        *p1 = p;
        *p2 = NULL;
        return 0;
    }

    len1 = off;
    len2 = p->tot_len - off;

    for (cut = p; cut->next != NULL && cut->next->tot_len > len2; 
        cut = cut->next);

    if (cut->next != NULL && cut->next->tot_len == len2) {
        /* That's great. The cut coincides with a pbuf boundary */
        head1 = p;
        head2 = cut->next;
        pbuf_ref(head2);
        pbuf_realloc(head1, len1);
    } else {
        /* The cut happen in the cut pbuf */
        const off_t cuf_off = cut->tot_len - len2;
        head1 = p;
        head2 = pbuf_alloc(PBUF_RAW, cut->len - cuf_off, PBUF_POOL);
        if (head2 == NULL) {
            fit_warn("%s: Failed to allocate pbuf\n", __func__);
            ret = -ENOMEM;
            goto err;
        }
        memcpy(head2->payload, cut->payload + cuf_off, cut->len - cuf_off);
        pbuf_chain(head2, cut->next);
        pbuf_realloc(head1, len1);
    }
    *p1 = head1;
    *p2 = head2;
    return 0;
err:
    *p1 = *p2 = NULL;
    return ret;
}