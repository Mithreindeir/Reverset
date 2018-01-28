#include "rmeta.h"

r_meta * r_meta_init()
{
	r_meta * meta = malloc(sizeof(r_meta));

	meta->type = r_tnone;
	meta->comment = NULL;
	meta->num_xrefto = 0;
	meta->xref_to = NULL;
	meta->num_xreffrom = 0;
	meta->xref_from = NULL;
	meta->num_addr = 0;
	meta->addresses = NULL;

	return meta;
}

void r_meta_destroy(r_meta * meta)
{
	if (!meta) return;

	if (meta->comment) free(meta->comment);
	if (meta->addresses) free(meta->addresses);
	if (meta->xref_to) free(meta->xref_to);
	if (meta->xref_from) free(meta->xref_from);

	free(meta);

}

void r_meta_add_addr(r_meta * meta, r64addr address)
{
	meta->num_addr++;
	if (meta->num_addr == 1) {
		meta->addresses = malloc(sizeof(r64addr));
	} else {
		meta->addresses = realloc(meta->addresses, meta->num_addr * (sizeof(r64addr)));
	}
	meta->addresses[meta->num_addr-1] = address;

}

int r_meta_find_addr(r_meta * meta, r64addr address)
{
	for (int i = 0; i < meta->num_addr; i++) {
		if (meta->addresses[i]==address) return 1;
	}
	return 0;
}