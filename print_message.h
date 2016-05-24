/****************************************************************************
 * Copyright (c) 2005 Integrated Medical Systems, Inc.
 * All Rights Reserved
 *
 * This is unpublished proprietary source code of Integrated Medical Systems.
 * The copyright notice above does not evidence any actual or intended
 * publication of such source code. Distribution in any form must be done with
 * the express written consent of Integrated Medical Systems, Inc.
 ****************************************************************************
 * File Name    : print_message.h
 * Author       : Greg Johnson
 *
 * Description  : debug-print an ethernet packet in hex and as characters
 *
 * 03/21/2007 gfj - Created.
 ****************************************************************************/
#ifndef PRINT_MESSAGE_H
#define PRINT_MESSAGE_H

#ifdef __cplusplus
extern "C" {
#endif

void print_message(char *buf, int msg_len);

#ifdef __cplusplus
}
#endif

#endif
