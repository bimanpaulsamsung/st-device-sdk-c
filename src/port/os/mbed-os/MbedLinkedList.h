/* ***************************************************************************
 *
 * Copyright (c) 2020 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#ifndef ST_DEVICE_SDK__MBEDLINKEDLIST_H_
#define ST_DEVICE_SDK__MBEDLINKEDLIST_H_

typedef bool (*compareFunc)(void *loopdata, void *searchdata);
typedef bool (*freeFunc)(void *searchdata);
typedef bool (*displayFunc)(void *searchdata);

typedef enum linked_list_error {
	LINKED_LIST_ERROR_NONE,
	LINKED_LIST_ERROR_NOT_FOUND
} linked_list_error_t;

class MbedLinkedList {
private:
	struct Node {
		void *data;
		Node *next;
	};
	Node *head = nullptr;

public:
	void insert(void *new_data);
	linked_list_error_t search(compareFunc fn, void *searchdata, void **ret);
	linked_list_error_t remove(compareFunc fn, void *searchdata, freeFunc fr);
	linked_list_error_t remove(void *deletedata);
	void display(displayFunc disp);
};

#endif /* ST_DEVICE_SDK__MBEDLINKEDLIST_H_ */
