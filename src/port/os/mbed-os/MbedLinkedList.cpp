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

#include "MbedLinkedList.h"

linked_list_error_t MbedLinkedList::insert(void *new_data) {
	if (!new_data)
		return LINKED_LIST_ERROR_INVALID_PARAM;

	Node *new_node = new Node;
	new_node->data = new_data;
	new_node->next = head;
	head = new_node;
	return LINKED_LIST_ERROR_NONE;
}

linked_list_error_t MbedLinkedList::search(compareFunc fn, void *searchdata, void **ret) {
	if (!fn || !searchdata || !ret)
		return LINKED_LIST_ERROR_INVALID_PARAM;

	Node *ptr;
	ptr = head;
	*ret = nullptr;
	while (ptr != nullptr) {
		if (fn(ptr->data, searchdata)) {
			*ret = ptr->data;
			return LINKED_LIST_ERROR_NONE;
		}
		ptr = ptr->next;
	}
	return LINKED_LIST_ERROR_NOT_FOUND;
}

linked_list_error_t MbedLinkedList::remove(void *deletedata) {
	if (!deletedata)
		return LINKED_LIST_ERROR_INVALID_PARAM;

	Node *ptr = nullptr, *back = nullptr;
	ptr = head;

	while (ptr != nullptr) {
		if (ptr->data == deletedata) {
			if (back == nullptr) {
				head = ptr->next;
			} else {
				back->next = ptr->next;
			}
			ptr->next = nullptr;
			ptr->data = nullptr;
			delete ptr;
			return LINKED_LIST_ERROR_NONE;
		}
		back = ptr;
		ptr = ptr->next;
	}
	return LINKED_LIST_ERROR_NOT_FOUND;
}

void MbedLinkedList::display(displayFunc disp) {
	if (!disp)
		return;

	Node *ptr;
	ptr = head;
	while (ptr != nullptr) {
		disp(ptr->data);
		ptr = ptr->next;
	}
}
