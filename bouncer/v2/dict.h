#ifndef DICT_H
#define DICT_H

#define SIZE_ARRAY 100

typedef struct dict DICT;

struct dict{
	u_short id_array[SIZE_ARRAY];
	struct in_addr add_array[SIZE_ARRAY];
};

#endif