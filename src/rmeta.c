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
	meta->address_types = NULL;
	meta->label = NULL;

	return meta;
}

void r_meta_destroy(r_meta * meta)
{
	if (!meta) return;

	if (meta->comment) free(meta->comment);
	if (meta->address_types) free(meta->address_types);
	if (meta->addresses) free(meta->addresses);
	if (meta->xref_to) free(meta->xref_to);
	if (meta->xref_from) free(meta->xref_from);
	if (meta->label) free(meta->label);

	free(meta);

}

void r_meta_add_addr(r_meta * meta, r64addr address, int type)
{
	//Insertion sort
	meta->num_addr++;
	if (meta->num_addr == 1) {
		meta->addresses = malloc(sizeof(r64addr));
	} else {
		meta->addresses = realloc(meta->addresses, meta->num_addr * (sizeof(r64addr)));
	}
	//meta->addresses[meta->num_addr-1] = address;
	if (meta->num_addr == 1) {
		meta->address_types = malloc(1);
	} else {
		meta->address_types = realloc(meta->address_types, meta->num_addr);
	}
	//meta->address_types[meta->num_addr-1] = type;
	int start = 0;
	for (int i = 0; i < (meta->num_addr-1); i++) {
		if (meta->addresses[i] < address)
			start++;
		else break;
	}
	if ((start+1) < meta->num_addr) {
		memmove(meta->addresses+start+1, meta->addresses+start, meta->num_addr-start);
		memmove(meta->address_types+start+1,meta->address_types+start, meta->num_addr-start);
	}

	meta->addresses[start] = address;
	meta->address_types[start] = type;
}

int r_meta_find_addr(r_meta * meta, r64addr address, int type)
{
	for (int i = 0; i < meta->num_addr; i++) {
		if (meta->addresses[i]>address) return 0;
		if (type == 2 && meta->addresses[i]==address) return i+1;
		else if (type == meta->address_types[i] && meta->addresses[i]==address) return i+1;
	}
	return 0;
}
