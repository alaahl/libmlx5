/*
 * Copyright (c) 2012 Mellanox Technologies, Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */


#if HAVE_CONFIG_H
#  include <config.h>
#endif /* HAVE_CONFIG_H */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>

#include <infiniband/opcode.h>

#include "mlx5.h"
#include "wqe.h"
#include "doorbell.h"

enum {
	MLX5_CQ_DOORBELL			= 0x20
};

enum {
	CQ_OK					=  0,
	CQ_EMPTY				= -1,
	CQ_POLL_ERR				= -2
};

#define MLX5_CQ_DB_REQ_NOT_SOL			(1 << 24)
#define MLX5_CQ_DB_REQ_NOT			(0 << 24)

enum {
	MLX5_CQE_SYNDROME_LOCAL_LENGTH_ERR		= 0x01,
	MLX5_CQE_SYNDROME_LOCAL_QP_OP_ERR		= 0x02,
	MLX5_CQE_SYNDROME_LOCAL_PROT_ERR		= 0x04,
	MLX5_CQE_SYNDROME_WR_FLUSH_ERR			= 0x05,
	MLX5_CQE_SYNDROME_MW_BIND_ERR			= 0x06,
	MLX5_CQE_SYNDROME_BAD_RESP_ERR			= 0x10,
	MLX5_CQE_SYNDROME_LOCAL_ACCESS_ERR		= 0x11,
	MLX5_CQE_SYNDROME_REMOTE_INVAL_REQ_ERR		= 0x12,
	MLX5_CQE_SYNDROME_REMOTE_ACCESS_ERR		= 0x13,
	MLX5_CQE_SYNDROME_REMOTE_OP_ERR			= 0x14,
	MLX5_CQE_SYNDROME_TRANSPORT_RETRY_EXC_ERR	= 0x15,
	MLX5_CQE_SYNDROME_RNR_RETRY_EXC_ERR		= 0x16,
	MLX5_CQE_SYNDROME_REMOTE_ABORTED_ERR		= 0x22,
};

enum {
	MLX5_CQE_OWNER_MASK	= 1,
	MLX5_CQE_REQ		= 0,
	MLX5_CQE_RESP_WR_IMM	= 1,
	MLX5_CQE_RESP_SEND	= 2,
	MLX5_CQE_RESP_SEND_IMM	= 3,
	MLX5_CQE_RESP_SEND_INV	= 4,
	MLX5_CQE_RESIZE_CQ	= 5,
	MLX5_CQE_REQ_ERR	= 13,
	MLX5_CQE_RESP_ERR	= 14,
	MLX5_CQE_INVALID	= 15,
};

enum {
	MLX5_CQ_MODIFY_RESEIZE = 0,
	MLX5_CQ_MODIFY_MODER = 1,
	MLX5_CQ_MODIFY_MAPPING = 2,
};

enum {
	MLX5_CQE_L2_OK = 1 << 0,
	MLX5_CQE_L3_OK = 1 << 1,
	MLX5_CQE_L4_OK = 1 << 2,
};

enum {
	MLX5_CQE_L3_HDR_TYPE_NONE = 0x0,
	MLX5_CQE_L3_HDR_TYPE_IPV6 = 0x1,
	MLX5_CQE_L3_HDR_TYPE_IPV4 = 0x2,
};

struct mlx5_err_cqe {
	uint8_t		rsvd0[32];
	uint32_t	srqn;
	uint8_t		rsvd1[18];
	uint8_t		vendor_err_synd;
	uint8_t		syndrome;
	uint32_t	s_wqe_opcode_qpn;
	uint16_t	wqe_counter;
	uint8_t		signature;
	uint8_t		op_own;
};

struct mlx5_cqe64 {
	uint8_t		rsvd0[17];
	uint8_t		ml_path;
	uint8_t		rsvd20[4];
	uint16_t	slid;
	uint32_t	flags_rqpn;
	uint8_t		hds_ip_ext;
	uint8_t		l4_hdr_type_etc;
	uint16_t	vlan_info;
	uint32_t	srqn_uidx;
	uint32_t	imm_inval_pkey;
	uint8_t		rsvd40[4];
	uint32_t	byte_cnt;
	__be64		timestamp;
	uint32_t	sop_drop_qpn;
	uint16_t	wqe_counter;
	uint8_t		signature;
	uint8_t		op_own;
};

int mlx5_stall_num_loop = 60;
int mlx5_stall_cq_poll_min = 60;
int mlx5_stall_cq_poll_max = 100000;
int mlx5_stall_cq_inc_step = 100;
int mlx5_stall_cq_dec_step = 10;

static inline uint8_t get_cqe_l3_hdr_type(struct mlx5_cqe64 *cqe)
{
	return (cqe->l4_hdr_type_etc >> 2) & 0x3;
}

static void *get_buf_cqe(struct mlx5_buf *buf, int n, int cqe_sz)
{
	return buf->buf + n * cqe_sz;
}

static void *get_cqe(struct mlx5_cq *cq, int n)
{
	return cq->active_buf->buf + n * cq->cqe_sz;
}

static void *get_sw_cqe(struct mlx5_cq *cq, int n)
{
	void *cqe = get_cqe(cq, n & cq->ibv_cq.cqe);
	struct mlx5_cqe64 *cqe64;

	cqe64 = (cq->cqe_sz == 64) ? cqe : cqe + 64;

	if (likely((cqe64->op_own) >> 4 != MLX5_CQE_INVALID) &&
	    !((cqe64->op_own & MLX5_CQE_OWNER_MASK) ^ !!(n & (cq->ibv_cq.cqe + 1)))) {
		return cqe;
	} else {
		return NULL;
	}
}

static void *next_cqe_sw(struct mlx5_cq *cq)
{
	return get_sw_cqe(cq, cq->cons_index);
}

static void update_cons_index(struct mlx5_cq *cq)
{
	cq->dbrec[MLX5_CQ_SET_CI] = htonl(cq->cons_index & 0xffffff);
}

static void handle_good_req(struct ibv_wc *wc, struct mlx5_cqe64 *cqe)
{
	switch (ntohl(cqe->sop_drop_qpn) >> 24) {
	case MLX5_OPCODE_RDMA_WRITE_IMM:
		wc->wc_flags |= IBV_WC_WITH_IMM;
	case MLX5_OPCODE_RDMA_WRITE:
		wc->opcode    = IBV_WC_RDMA_WRITE;
		break;
	case MLX5_OPCODE_SEND_IMM:
		wc->wc_flags |= IBV_WC_WITH_IMM;
	case MLX5_OPCODE_SEND:
	case MLX5_OPCODE_SEND_INVAL:
		wc->opcode    = IBV_WC_SEND;
		break;
	case MLX5_OPCODE_RDMA_READ:
		wc->opcode    = IBV_WC_RDMA_READ;
		wc->byte_len  = ntohl(cqe->byte_cnt);
		break;
	case MLX5_OPCODE_ATOMIC_CS:
		wc->opcode    = IBV_WC_COMP_SWAP;
		wc->byte_len  = 8;
		break;
	case MLX5_OPCODE_ATOMIC_FA:
		wc->opcode    = IBV_WC_FETCH_ADD;
		wc->byte_len  = 8;
		break;
	case MLX5_OPCODE_BIND_MW:
		wc->opcode    = IBV_WC_BIND_MW;
		break;
	}
}

union wc_buffer {
	uint8_t		*b8;
	uint16_t	*b16;
	uint32_t	*b32;
	uint64_t	*b64;
};

#define IS_IN_WC_FLAGS(yes, no, maybe, flag) (((yes) & (flag)) ||    \
					      (!((no) & (flag)) && \
					       ((maybe) & (flag))))
static inline void handle_good_req_ex(struct ibv_wc_ex *wc_ex,
				      union wc_buffer *pwc_buffer,
				      struct mlx5_cqe64 *cqe,
				      uint64_t wc_flags,
				      uint64_t wc_flags_yes,
				      uint64_t wc_flags_no,
				      uint32_t qpn, uint64_t *wc_flags_out)
	ALWAYS_INLINE;
static inline void handle_good_req_ex(struct ibv_wc_ex *wc_ex,
				      union wc_buffer *pwc_buffer,
				      struct mlx5_cqe64 *cqe,
				      uint64_t wc_flags,
				      uint64_t wc_flags_yes,
				      uint64_t wc_flags_no,
				      uint32_t qpn, uint64_t *wc_flags_out)
{
	union wc_buffer wc_buffer = *pwc_buffer;

	switch (ntohl(cqe->sop_drop_qpn) >> 24) {
	case MLX5_OPCODE_RDMA_WRITE_IMM:
		*wc_flags_out |= IBV_WC_EX_IMM;
	case MLX5_OPCODE_RDMA_WRITE:
		wc_ex->opcode    = IBV_WC_RDMA_WRITE;
		if (IS_IN_WC_FLAGS(wc_flags_yes, wc_flags_no, wc_flags,
				   IBV_WC_EX_WITH_BYTE_LEN))
			wc_buffer.b32++;
		if (IS_IN_WC_FLAGS(wc_flags_yes, wc_flags_no, wc_flags,
				   IBV_WC_EX_WITH_IMM))
			wc_buffer.b32++;
		break;
	case MLX5_OPCODE_SEND_IMM:
		*wc_flags_out |= IBV_WC_EX_IMM;
	case MLX5_OPCODE_SEND:
	case MLX5_OPCODE_SEND_INVAL:
		wc_ex->opcode    = IBV_WC_SEND;
		if (IS_IN_WC_FLAGS(wc_flags_yes, wc_flags_no, wc_flags,
				   IBV_WC_EX_WITH_BYTE_LEN))
			wc_buffer.b32++;
		if (IS_IN_WC_FLAGS(wc_flags_yes, wc_flags_no, wc_flags,
				   IBV_WC_EX_WITH_IMM))
			wc_buffer.b32++;
		break;
	case MLX5_OPCODE_RDMA_READ:
		wc_ex->opcode    = IBV_WC_RDMA_READ;
		if (IS_IN_WC_FLAGS(wc_flags_yes, wc_flags_no, wc_flags,
				   IBV_WC_EX_WITH_BYTE_LEN)) {
			*wc_buffer.b32++ = ntohl(cqe->byte_cnt);
			*wc_flags_out |= IBV_WC_EX_WITH_BYTE_LEN;
		}
		if (IS_IN_WC_FLAGS(wc_flags_yes, wc_flags_no, wc_flags,
				   IBV_WC_EX_WITH_IMM))
			wc_buffer.b32++;
		break;
	case MLX5_OPCODE_ATOMIC_CS:
		wc_ex->opcode    = IBV_WC_COMP_SWAP;
		if (IS_IN_WC_FLAGS(wc_flags_yes, wc_flags_no, wc_flags,
				   IBV_WC_EX_WITH_BYTE_LEN)) {
			*wc_buffer.b32++ = 8;
			*wc_flags_out |= IBV_WC_EX_WITH_BYTE_LEN;
		}
		if (IS_IN_WC_FLAGS(wc_flags_yes, wc_flags_no, wc_flags,
				   IBV_WC_EX_WITH_IMM))
			wc_buffer.b32++;
		break;
	case MLX5_OPCODE_ATOMIC_FA:
		wc_ex->opcode    = IBV_WC_FETCH_ADD;
		if (IS_IN_WC_FLAGS(wc_flags_yes, wc_flags_no, wc_flags,
				   IBV_WC_EX_WITH_BYTE_LEN)) {
			*wc_buffer.b32++ = 8;
			*wc_flags_out |= IBV_WC_EX_WITH_BYTE_LEN;
		}
		if (IS_IN_WC_FLAGS(wc_flags_yes, wc_flags_no, wc_flags,
				   IBV_WC_EX_WITH_IMM))
			wc_buffer.b32++;
		break;
	case MLX5_OPCODE_BIND_MW:
		wc_ex->opcode    = IBV_WC_BIND_MW;
		if (IS_IN_WC_FLAGS(wc_flags_yes, wc_flags_no, wc_flags,
				   IBV_WC_EX_WITH_BYTE_LEN))
			wc_buffer.b32++;
		if (IS_IN_WC_FLAGS(wc_flags_yes, wc_flags_no, wc_flags,
				   IBV_WC_EX_WITH_IMM))
			wc_buffer.b32++;
		break;
	}

	if (IS_IN_WC_FLAGS(wc_flags_yes, wc_flags_no, wc_flags,
			   IBV_WC_EX_WITH_QP_NUM)) {
		*wc_buffer.b32++ = qpn;
		*wc_flags_out |= IBV_WC_EX_WITH_QP_NUM;
	}

	*pwc_buffer = wc_buffer;
}

static int handle_responder(struct ibv_wc *wc, struct mlx5_cqe64 *cqe,
			    struct mlx5_qp *qp, struct mlx5_srq *srq)
{
	uint16_t	wqe_ctr;
	struct mlx5_wq *wq;
	uint8_t g;
	int err = 0;

	wc->byte_len = ntohl(cqe->byte_cnt);
	if (srq) {
		wqe_ctr = ntohs(cqe->wqe_counter);
		wc->wr_id = srq->wrid[wqe_ctr];
		mlx5_free_srq_wqe(srq, wqe_ctr);
		if (cqe->op_own & MLX5_INLINE_SCATTER_32)
			err = mlx5_copy_to_recv_srq(srq, wqe_ctr, cqe,
						    wc->byte_len);
		else if (cqe->op_own & MLX5_INLINE_SCATTER_64)
			err = mlx5_copy_to_recv_srq(srq, wqe_ctr, cqe - 1,
						    wc->byte_len);
	} else {
		wq	  = &qp->rq;
		wqe_ctr = wq->tail & (wq->wqe_cnt - 1);
		wc->wr_id = wq->wrid[wqe_ctr];
		++wq->tail;
		if (cqe->op_own & MLX5_INLINE_SCATTER_32)
			err = mlx5_copy_to_recv_wqe(qp, wqe_ctr, cqe,
						    wc->byte_len);
		else if (cqe->op_own & MLX5_INLINE_SCATTER_64)
			err = mlx5_copy_to_recv_wqe(qp, wqe_ctr, cqe - 1,
						    wc->byte_len);
		if (qp->qp_cap_cache & MLX5_RX_CSUM_VALID)
			wc->wc_flags |= (!!(cqe->hds_ip_ext & MLX5_CQE_L4_OK) &
					 !!(cqe->hds_ip_ext & MLX5_CQE_L3_OK) &
					(get_cqe_l3_hdr_type(cqe) ==
					MLX5_CQE_L3_HDR_TYPE_IPV4)) <<
					IBV_WC_IP_CSUM_OK_SHIFT;
	}
	if (err)
		return err;

	wc->byte_len = ntohl(cqe->byte_cnt);

	switch (cqe->op_own >> 4) {
	case MLX5_CQE_RESP_WR_IMM:
		wc->opcode	= IBV_WC_RECV_RDMA_WITH_IMM;
		wc->wc_flags	|= IBV_WC_WITH_IMM;
		wc->imm_data = cqe->imm_inval_pkey;
		break;
	case MLX5_CQE_RESP_SEND:
		wc->opcode   = IBV_WC_RECV;
		break;
	case MLX5_CQE_RESP_SEND_IMM:
		wc->opcode	= IBV_WC_RECV;
		wc->wc_flags	|= IBV_WC_WITH_IMM;
		wc->imm_data = cqe->imm_inval_pkey;
		break;
	}
	wc->slid	   = ntohs(cqe->slid);
	wc->sl		   = (ntohl(cqe->flags_rqpn) >> 24) & 0xf;
	wc->src_qp	   = ntohl(cqe->flags_rqpn) & 0xffffff;
	wc->dlid_path_bits = cqe->ml_path & 0x7f;
	g = (ntohl(cqe->flags_rqpn) >> 28) & 3;
	wc->wc_flags |= g ? IBV_WC_GRH : 0;
	wc->pkey_index     = ntohl(cqe->imm_inval_pkey) & 0xffff;

	return IBV_WC_SUCCESS;
}

static inline int handle_responder_ex(struct ibv_wc_ex *wc_ex,
				      union wc_buffer *pwc_buffer,
				      struct mlx5_cqe64 *cqe,
				      struct mlx5_qp *qp, struct mlx5_srq *srq,
				      uint64_t wc_flags, uint64_t wc_flags_yes,
				      uint64_t wc_flags_no, uint32_t qpn,
				      uint64_t *wc_flags_out)
	ALWAYS_INLINE;
static inline int handle_responder_ex(struct ibv_wc_ex *wc_ex,
				      union wc_buffer *pwc_buffer,
				      struct mlx5_cqe64 *cqe,
				      struct mlx5_qp *qp, struct mlx5_srq *srq,
				      uint64_t wc_flags, uint64_t wc_flags_yes,
				      uint64_t wc_flags_no, uint32_t qpn,
				      uint64_t *wc_flags_out)
{
	uint16_t wqe_ctr;
	struct mlx5_wq *wq;
	uint8_t g;
	union wc_buffer wc_buffer = *pwc_buffer;
	int err = 0;
	uint32_t byte_len = ntohl(cqe->byte_cnt);

	if (IS_IN_WC_FLAGS(wc_flags_yes, wc_flags_no, wc_flags,
			   IBV_WC_EX_WITH_BYTE_LEN)) {
		*wc_buffer.b32++ = byte_len;
		*wc_flags_out |= IBV_WC_EX_WITH_BYTE_LEN;
	}
	if (srq) {
		wqe_ctr = ntohs(cqe->wqe_counter);
		wc_ex->wr_id = srq->wrid[wqe_ctr];
		mlx5_free_srq_wqe(srq, wqe_ctr);
		if (cqe->op_own & MLX5_INLINE_SCATTER_32)
			err = mlx5_copy_to_recv_srq(srq, wqe_ctr, cqe,
						    byte_len);
		else if (cqe->op_own & MLX5_INLINE_SCATTER_64)
			err = mlx5_copy_to_recv_srq(srq, wqe_ctr, cqe - 1,
						    byte_len);
	} else {
		wq	  = &qp->rq;
		wqe_ctr = wq->tail & (wq->wqe_cnt - 1);
		wc_ex->wr_id = wq->wrid[wqe_ctr];
		++wq->tail;
		if (cqe->op_own & MLX5_INLINE_SCATTER_32)
			err = mlx5_copy_to_recv_wqe(qp, wqe_ctr, cqe,
						    byte_len);
		else if (cqe->op_own & MLX5_INLINE_SCATTER_64)
			err = mlx5_copy_to_recv_wqe(qp, wqe_ctr, cqe - 1,
						    byte_len);
		if (qp->qp_cap_cache & MLX5_RX_CSUM_VALID)
			*wc_flags_out |= ((!!(cqe->hds_ip_ext &
					(MLX5_CQE_L4_OK | MLX5_CQE_L3_OK))) &
					(get_cqe_l3_hdr_type(cqe) ==
					MLX5_CQE_L3_HDR_TYPE_IPV4)) <<
					IBV_WC_IP_CSUM_OK_SHIFT;
	}
	if (err)
		return err;

	switch (cqe->op_own >> 4) {
	case MLX5_CQE_RESP_WR_IMM:
		wc_ex->opcode	= IBV_WC_RECV_RDMA_WITH_IMM;
		*wc_flags_out	|= IBV_WC_EX_IMM;
		if (IS_IN_WC_FLAGS(wc_flags_yes, wc_flags_no, wc_flags,
				   IBV_WC_EX_WITH_IMM)) {
			*wc_buffer.b32++ = ntohl(cqe->byte_cnt);
			*wc_flags_out |= IBV_WC_EX_WITH_IMM;
		}
		break;
	case MLX5_CQE_RESP_SEND:
		wc_ex->opcode   = IBV_WC_RECV;
		if (IS_IN_WC_FLAGS(wc_flags_yes, wc_flags_no, wc_flags,
				   IBV_WC_EX_WITH_IMM))
			wc_buffer.b32++;
		break;
	case MLX5_CQE_RESP_SEND_IMM:
		wc_ex->opcode	= IBV_WC_RECV;
		*wc_flags_out	|= IBV_WC_EX_WITH_IMM;
		if (IS_IN_WC_FLAGS(wc_flags_yes, wc_flags_no, wc_flags,
				   IBV_WC_EX_WITH_IMM)) {
			*wc_buffer.b32++ = ntohl(cqe->imm_inval_pkey);
			*wc_flags_out |= IBV_WC_EX_WITH_IMM;
		}
		break;
	}
	if (IS_IN_WC_FLAGS(wc_flags_yes, wc_flags_no, wc_flags,
			   IBV_WC_EX_WITH_QP_NUM)) {
		*wc_buffer.b32++ = qpn;
		*wc_flags_out |= IBV_WC_EX_WITH_QP_NUM;
	}
	if (IS_IN_WC_FLAGS(wc_flags_yes, wc_flags_no, wc_flags,
			   IBV_WC_EX_WITH_SRC_QP)) {
		*wc_buffer.b32++ = ntohl(cqe->flags_rqpn) & 0xffffff;
		*wc_flags_out |= IBV_WC_EX_WITH_SRC_QP;
	}
	if (IS_IN_WC_FLAGS(wc_flags_yes, wc_flags_no, wc_flags,
			   IBV_WC_EX_WITH_PKEY_INDEX)) {
		*wc_buffer.b16++ = ntohl(cqe->imm_inval_pkey) & 0xffff;
		*wc_flags_out |= IBV_WC_EX_WITH_PKEY_INDEX;
	}
	if (IS_IN_WC_FLAGS(wc_flags_yes, wc_flags_no, wc_flags,
			   IBV_WC_EX_WITH_SLID)) {
		*wc_buffer.b16++ = ntohs(cqe->slid);
		*wc_flags_out |= IBV_WC_EX_WITH_SLID;
	}
	if (IS_IN_WC_FLAGS(wc_flags_yes, wc_flags_no, wc_flags,
			   IBV_WC_EX_WITH_SL)) {
		*wc_buffer.b8++ = (ntohl(cqe->flags_rqpn) >> 24) & 0xf;
		*wc_flags_out |= IBV_WC_EX_WITH_SL;
	}
	if (IS_IN_WC_FLAGS(wc_flags_yes, wc_flags_no, wc_flags,
			   IBV_WC_EX_WITH_DLID_PATH_BITS)) {
		*wc_buffer.b8++ = cqe->ml_path & 0x7f;
		*wc_flags_out |= IBV_WC_EX_WITH_DLID_PATH_BITS;
	}

	g = (ntohl(cqe->flags_rqpn) >> 28) & 3;
	*wc_flags_out |= g ? IBV_WC_EX_GRH : 0;

	*pwc_buffer = wc_buffer;
	return IBV_WC_SUCCESS;
}

static void dump_cqe(FILE *fp, void *buf)
{
	uint32_t *p = buf;
	int i;

	for (i = 0; i < 16; i += 4)
		fprintf(fp, "%08x %08x %08x %08x\n", ntohl(p[i]), ntohl(p[i + 1]),
			ntohl(p[i + 2]), ntohl(p[i + 3]));
}

static void mlx5_handle_error_cqe(struct mlx5_err_cqe *cqe,
				  uint32_t *pwc_status,
				  uint32_t *pwc_vendor_err)
{
	switch (cqe->syndrome) {
	case MLX5_CQE_SYNDROME_LOCAL_LENGTH_ERR:
		*pwc_status = IBV_WC_LOC_LEN_ERR;
		break;
	case MLX5_CQE_SYNDROME_LOCAL_QP_OP_ERR:
		*pwc_status = IBV_WC_LOC_QP_OP_ERR;
		break;
	case MLX5_CQE_SYNDROME_LOCAL_PROT_ERR:
		*pwc_status = IBV_WC_LOC_PROT_ERR;
		break;
	case MLX5_CQE_SYNDROME_WR_FLUSH_ERR:
		*pwc_status = IBV_WC_WR_FLUSH_ERR;
		break;
	case MLX5_CQE_SYNDROME_MW_BIND_ERR:
		*pwc_status = IBV_WC_MW_BIND_ERR;
		break;
	case MLX5_CQE_SYNDROME_BAD_RESP_ERR:
		*pwc_status = IBV_WC_BAD_RESP_ERR;
		break;
	case MLX5_CQE_SYNDROME_LOCAL_ACCESS_ERR:
		*pwc_status = IBV_WC_LOC_ACCESS_ERR;
		break;
	case MLX5_CQE_SYNDROME_REMOTE_INVAL_REQ_ERR:
		*pwc_status = IBV_WC_REM_INV_REQ_ERR;
		break;
	case MLX5_CQE_SYNDROME_REMOTE_ACCESS_ERR:
		*pwc_status = IBV_WC_REM_ACCESS_ERR;
		break;
	case MLX5_CQE_SYNDROME_REMOTE_OP_ERR:
		*pwc_status = IBV_WC_REM_OP_ERR;
		break;
	case MLX5_CQE_SYNDROME_TRANSPORT_RETRY_EXC_ERR:
		*pwc_status = IBV_WC_RETRY_EXC_ERR;
		break;
	case MLX5_CQE_SYNDROME_RNR_RETRY_EXC_ERR:
		*pwc_status = IBV_WC_RNR_RETRY_EXC_ERR;
		break;
	case MLX5_CQE_SYNDROME_REMOTE_ABORTED_ERR:
		*pwc_status = IBV_WC_REM_ABORT_ERR;
		break;
	default:
		*pwc_status = IBV_WC_GENERAL_ERR;
		break;
	}

	*pwc_vendor_err = cqe->vendor_err_synd;
}

#if defined(__x86_64__) || defined (__i386__)
static inline unsigned long get_cycles()
{
	uint32_t low, high;
	uint64_t val;
	asm volatile ("rdtsc" : "=a" (low), "=d" (high));
	val = high;
	val = (val << 32) | low;
	return val;
}

static void mlx5_stall_poll_cq()
{
	int i;

	for (i = 0; i < mlx5_stall_num_loop; i++)
		(void)get_cycles();
}
static void mlx5_stall_cycles_poll_cq(uint64_t cycles)
{
	while (get_cycles()  <  cycles)
		; /* Nothing */
}
static void mlx5_get_cycles(uint64_t *cycles)
{
	*cycles = get_cycles();
}
#else
static void mlx5_stall_poll_cq()
{
}
static void mlx5_stall_cycles_poll_cq(uint64_t cycles)
{
}
static void mlx5_get_cycles(uint64_t *cycles)
{
}
#endif

static inline struct mlx5_qp *get_req_context(struct mlx5_context *mctx,
					      struct mlx5_resource **cur_rsc,
					      uint32_t rsn, int cqe_ver)
					      ALWAYS_INLINE;
static inline struct mlx5_qp *get_req_context(struct mlx5_context *mctx,
					      struct mlx5_resource **cur_rsc,
					      uint32_t rsn, int cqe_ver)
{
	if (!*cur_rsc || (rsn != (*cur_rsc)->rsn))
		*cur_rsc = cqe_ver ? mlx5_find_uidx(mctx, rsn) :
				      (struct mlx5_resource *)mlx5_find_qp(mctx, rsn);

	return rsc_to_mqp(*cur_rsc);
}

static inline int get_resp_ctx_v1(struct mlx5_context *mctx,
				  struct mlx5_resource **cur_rsc,
				  struct mlx5_srq **cur_srq,
				  uint32_t uidx, uint8_t *is_srq)
				  ALWAYS_INLINE;
static inline int get_resp_ctx_v1(struct mlx5_context *mctx,
				  struct mlx5_resource **cur_rsc,
				  struct mlx5_srq **cur_srq,
				  uint32_t uidx, uint8_t *is_srq)
{
	struct mlx5_qp *mqp;

	if (!*cur_rsc || (uidx != (*cur_rsc)->rsn)) {
		*cur_rsc = mlx5_find_uidx(mctx, uidx);
		if (unlikely(!*cur_rsc))
			return CQ_POLL_ERR;
	}

	switch ((*cur_rsc)->type) {
	case MLX5_RSC_TYPE_QP:
		mqp = rsc_to_mqp(*cur_rsc);
		if (mqp->verbs_qp.qp.srq) {
			*cur_srq = to_msrq(mqp->verbs_qp.qp.srq);
			*is_srq = 1;
		}
		break;
	case MLX5_RSC_TYPE_XSRQ:
		*cur_srq = rsc_to_msrq(*cur_rsc);
		*is_srq = 1;
		break;
	default:
		return CQ_POLL_ERR;
	}

	return CQ_OK;
}

static inline int get_qp_ctx(struct mlx5_context *mctx,
			     struct mlx5_resource **cur_rsc,
			     uint32_t qpn)
			       ALWAYS_INLINE;
static inline int get_qp_ctx(struct mlx5_context *mctx,
			     struct mlx5_resource **cur_rsc,
			     uint32_t qpn)
{
	if (!*cur_rsc || (qpn != (*cur_rsc)->rsn)) {
		/*
		 * We do not have to take the QP table lock here,
		 * because CQs will be locked while QPs are removed
		 * from the table.
		 */
		*cur_rsc = (struct mlx5_resource *)mlx5_find_qp(mctx, qpn);
		if (unlikely(!*cur_rsc))
			return CQ_POLL_ERR;
	}

	return CQ_OK;
}

static inline int get_srq_ctx(struct mlx5_context *mctx,
			      struct mlx5_srq **cur_srq,
			      uint32_t srqn_uidx)
			      ALWAYS_INLINE;
static inline int get_srq_ctx(struct mlx5_context *mctx,
			      struct mlx5_srq **cur_srq,
			      uint32_t srqn)
{
	if (!*cur_srq || (srqn != (*cur_srq)->srqn)) {
		*cur_srq = mlx5_find_srq(mctx, srqn);
		if (unlikely(!*cur_srq))
			return CQ_POLL_ERR;
	}

	return CQ_OK;
}

static inline int get_cur_rsc(struct mlx5_context *mctx,
			      int cqe_ver,
			      uint32_t qpn,
			      uint32_t srqn_uidx,
			      struct mlx5_resource **cur_rsc,
			      struct mlx5_srq **cur_srq,
			      uint8_t *is_srq)
{
	int err;

	if (cqe_ver) {
		err = get_resp_ctx_v1(mctx, cur_rsc, cur_srq, srqn_uidx,
				      is_srq);
	} else {
		if (srqn_uidx) {
			*is_srq = 1;
			err = get_srq_ctx(mctx, cur_srq, srqn_uidx);
		} else {
			err = get_qp_ctx(mctx, cur_rsc, qpn);
		}
	}

	return err;

}

static inline void dump_cqe_debug(FILE *fp, struct mlx5_cq *cq,
				  struct mlx5_cqe64 *cqe64) ALWAYS_INLINE;
static inline void dump_cqe_debug(FILE *fp, struct mlx5_cq *cq,
				  struct mlx5_cqe64 *cqe64)
{
#ifdef MLX5_DEBUG
	if (mlx5_debug_mask & MLX5_DBG_CQ_CQE) {
		mlx5_dbg(fp, MLX5_DBG_CQ_CQE, "dump cqe for cqn 0x%x:\n", cq->cqn);
		dump_cqe(fp, cqe64);
	}
#endif
}

inline int mlx5_poll_one_cqe_req(struct mlx5_cq *cq,
				 struct mlx5_resource **cur_rsc,
				 void *cqe, uint32_t qpn, int cqe_ver,
				 uint64_t *wr_id) ALWAYS_INLINE;
inline int mlx5_poll_one_cqe_req(struct mlx5_cq *cq,
				 struct mlx5_resource **cur_rsc,
				 void *cqe, uint32_t qpn, int cqe_ver,
				 uint64_t *wr_id)
{
	struct mlx5_context *mctx = to_mctx(cq->ibv_cq.context);
	struct mlx5_qp *mqp = NULL;
	struct mlx5_cqe64 *cqe64 = (cq->cqe_sz == 64) ? cqe : cqe + 64;
	uint32_t byte_len = ntohl(cqe64->byte_cnt);
	struct mlx5_wq *wq;
	uint16_t wqe_ctr;
	int err;
	int idx;

	mqp = get_req_context(mctx, cur_rsc,
			      (cqe_ver ? (ntohl(cqe64->srqn_uidx) & 0xffffff) : qpn),
			      cqe_ver);
	if (unlikely(!mqp))
		return CQ_POLL_ERR;
	wq = &mqp->sq;
	wqe_ctr = ntohs(cqe64->wqe_counter);
	idx = wqe_ctr & (wq->wqe_cnt - 1);
	if (cqe64->op_own & MLX5_INLINE_SCATTER_32)
		err = mlx5_copy_to_send_wqe(mqp, wqe_ctr, cqe,
					    byte_len);
	else if (cqe64->op_own & MLX5_INLINE_SCATTER_64)
		err = mlx5_copy_to_send_wqe(mqp, wqe_ctr, cqe - 1,
					    byte_len);
	else
		err = 0;

	wq->tail = wq->wqe_head[idx] + 1;
	*wr_id = wq->wrid[idx];

	return err;
}

inline int mlx5_poll_one_cqe_resp(struct mlx5_context *mctx,
				  struct mlx5_resource **cur_rsc,
				  struct mlx5_srq **cur_srq,
				  struct mlx5_cqe64 *cqe64, int cqe_ver,
				  uint32_t qpn, uint8_t *is_srq)
	ALWAYS_INLINE;
inline int mlx5_poll_one_cqe_resp(struct mlx5_context *mctx,
				  struct mlx5_resource **cur_rsc,
				  struct mlx5_srq **cur_srq,
				  struct mlx5_cqe64 *cqe64, int cqe_ver,
				  uint32_t qpn, uint8_t *is_srq)
{
	uint32_t srqn_uidx = ntohl(cqe64->srqn_uidx) & 0xffffff;
	int err;

	if (cqe_ver) {
		err = get_resp_ctx_v1(mctx, cur_rsc, cur_srq, srqn_uidx, is_srq);
	} else {
		if (srqn_uidx) {
			err = get_srq_ctx(mctx, cur_srq, srqn_uidx);
			*is_srq = 1;
		} else {
			err = get_qp_ctx(mctx, cur_rsc, qpn);
		}
	}

	return err;
}

inline int mlx5_poll_one_cqe_err(struct mlx5_context *mctx,
				 struct mlx5_resource **cur_rsc,
				 struct mlx5_srq **cur_srq,
				 struct mlx5_cqe64 *cqe64, int cqe_ver,
				 uint32_t qpn, uint32_t *pwc_status,
				 uint32_t *pwc_vendor_err,
				 uint64_t *pwc_wr_id, uint8_t opcode)
	ALWAYS_INLINE;
inline int mlx5_poll_one_cqe_err(struct mlx5_context *mctx,
				 struct mlx5_resource **cur_rsc,
				 struct mlx5_srq **cur_srq,
				 struct mlx5_cqe64 *cqe64, int cqe_ver,
				 uint32_t qpn, uint32_t *pwc_status,
				 uint32_t *pwc_vendor_err,
				 uint64_t *pwc_wr_id, uint8_t opcode)
{
	uint32_t srqn_uidx = ntohl(cqe64->srqn_uidx) & 0xffffff;
	struct mlx5_err_cqe *ecqe = (struct mlx5_err_cqe *)cqe64;
	int err = CQ_OK;

	mlx5_handle_error_cqe(ecqe, pwc_status, pwc_vendor_err);
	if (unlikely(ecqe->syndrome != MLX5_CQE_SYNDROME_WR_FLUSH_ERR &&
		     ecqe->syndrome != MLX5_CQE_SYNDROME_TRANSPORT_RETRY_EXC_ERR)) {
		FILE *fp = mctx->dbg_fp;

		fprintf(fp, PFX "%s: got completion with error:\n",
			mctx->hostname);
		dump_cqe(fp, ecqe);
		if (mlx5_freeze_on_error_cqe) {
			fprintf(fp, PFX "freezing at poll cq...");
			while (1)
				sleep(10);
		}
	}

	if (opcode == MLX5_CQE_REQ_ERR) {
		struct mlx5_qp *mqp = NULL;
		struct mlx5_wq *wq;
		uint16_t wqe_ctr;
		int idx;

		mqp = get_req_context(mctx, cur_rsc, (cqe_ver ? srqn_uidx : qpn), cqe_ver);
		if (unlikely(!mqp))
			return CQ_POLL_ERR;
		wq = &mqp->sq;
		wqe_ctr = ntohs(cqe64->wqe_counter);
		idx = wqe_ctr & (wq->wqe_cnt - 1);
		*pwc_wr_id = wq->wrid[idx];
		wq->tail = wq->wqe_head[idx] + 1;
	} else {
		uint8_t is_srq = 0;

		err = get_cur_rsc(mctx, cqe_ver, qpn, srqn_uidx,
				  cur_rsc, cur_srq, &is_srq);

		if (unlikely(err))
			return CQ_POLL_ERR;

		if (is_srq) {
			uint16_t wqe_ctr = ntohs(cqe64->wqe_counter);

			*pwc_wr_id = (*cur_srq)->wrid[wqe_ctr];
			mlx5_free_srq_wqe(*cur_srq, wqe_ctr);
		} else {
			struct mlx5_qp *mqp = rsc_to_mqp(*cur_rsc);
			struct mlx5_wq *wq;

			wq = &mqp->rq;
			*pwc_wr_id = wq->wrid[wq->tail & (wq->wqe_cnt - 1)];
			++wq->tail;
		}
	}

	return err;
}

#define IS_IN_WC_FLAGS(yes, no, maybe, flag) (((yes) & (flag)) ||    \
					      (!((no) & (flag)) && \
					       ((maybe) & (flag))))
static inline int mlx5_poll_one(struct mlx5_cq *cq,
			 struct mlx5_resource **cur_rsc,
			 struct mlx5_srq **cur_srq,
			 struct ibv_wc *wc, int cqe_ver)
			 ALWAYS_INLINE;
static inline int mlx5_poll_one(struct mlx5_cq *cq,
			 struct mlx5_resource **cur_rsc,
			 struct mlx5_srq **cur_srq,
			 struct ibv_wc *wc, int cqe_ver)
{
	struct mlx5_cqe64 *cqe64;
	void *cqe;
	uint32_t qpn;
	uint8_t opcode;
	int err;
	struct mlx5_context *mctx = to_mctx(cq->ibv_cq.context);

	cqe = next_cqe_sw(cq);
	if (!cqe)
		return CQ_EMPTY;

	cqe64 = (cq->cqe_sz == 64) ? cqe : cqe + 64;

	opcode = cqe64->op_own >> 4;
	++cq->cons_index;

	VALGRIND_MAKE_MEM_DEFINED(cqe64, sizeof *cqe64);

	/*
	 * Make sure we read CQ entry contents after we've checked the
	 * ownership bit.
	 */
	rmb();

	dump_cqe_debug(mctx->dbg_fp, cq, cqe64);

	qpn = ntohl(cqe64->sop_drop_qpn) & 0xffffff;
	wc->wc_flags = 0;

	switch (opcode) {
	case MLX5_CQE_REQ:
		err = mlx5_poll_one_cqe_req(cq, cur_rsc, cqe, qpn, cqe_ver,
					    &wc->wr_id);
		handle_good_req(wc, cqe64);
		wc->status = err;
		break;

	case MLX5_CQE_RESP_WR_IMM:
	case MLX5_CQE_RESP_SEND:
	case MLX5_CQE_RESP_SEND_IMM:
	case MLX5_CQE_RESP_SEND_INV: {
		uint8_t is_srq = 0;

		err = mlx5_poll_one_cqe_resp(mctx, cur_rsc, cur_srq, cqe64,
					     cqe_ver, qpn, &is_srq);
		if (unlikely(err))
			return CQ_POLL_ERR;

		wc->status = handle_responder(wc, cqe64, rsc_to_mqp(*cur_rsc),
					      is_srq ? *cur_srq : NULL);
		break;
	}
	case MLX5_CQE_RESIZE_CQ:
		break;
	case MLX5_CQE_REQ_ERR:
	case MLX5_CQE_RESP_ERR:
		err = mlx5_poll_one_cqe_err(mctx, cur_rsc, cur_srq, cqe64,
					    cqe_ver, qpn, &wc->status,
					    &wc->vendor_err, &wc->wr_id,
					    opcode);
		if (err != CQ_OK)
			return CQ_POLL_ERR;
		break;
	}

	wc->qp_num = qpn;
	return CQ_OK;
}

static inline int _mlx5_poll_one_ex(struct mlx5_cq *cq,
				    struct mlx5_resource **cur_rsc,
				    struct mlx5_srq **cur_srq,
				    struct ibv_wc_ex **pwc_ex,
				    uint64_t wc_flags,
				    uint64_t wc_flags_yes, uint64_t wc_flags_no,
				    int cqe_ver)
	ALWAYS_INLINE;
static inline int _mlx5_poll_one_ex(struct mlx5_cq *cq,
				    struct mlx5_resource **cur_rsc,
				    struct mlx5_srq **cur_srq,
				    struct ibv_wc_ex **pwc_ex,
				    uint64_t wc_flags,
				    uint64_t wc_flags_yes, uint64_t wc_flags_no,
				    int cqe_ver)
{
	struct mlx5_cqe64 *cqe64;
	void *cqe;
	uint32_t qpn;
	uint8_t opcode;
	int err;
	struct mlx5_context *mctx = to_mctx(cq->ibv_cq.context);
	struct ibv_wc_ex *wc_ex = *pwc_ex;
	union wc_buffer wc_buffer;
	uint64_t wc_flags_out = 0;

	cqe = next_cqe_sw(cq);
	if (!cqe)
		return CQ_EMPTY;

	cqe64 = (cq->cqe_sz == 64) ? cqe : cqe + 64;

	opcode = cqe64->op_own >> 4;
	++cq->cons_index;

	VALGRIND_MAKE_MEM_DEFINED(cqe64, sizeof *cqe64);

	/*
	 * Make sure we read CQ entry contents after we've checked the
	 * ownership bit.
	 */
	rmb();

	dump_cqe_debug(mctx->dbg_fp, cq, cqe64);

	qpn = ntohl(cqe64->sop_drop_qpn) & 0xffffff;
	wc_buffer.b64 = (uint64_t *)&wc_ex->buffer;
	wc_ex->wc_flags = 0;
	wc_ex->reserved = 0;

	if (IS_IN_WC_FLAGS(wc_flags_yes, wc_flags_no, wc_flags,
			   IBV_WC_EX_WITH_COMPLETION_TIMESTAMP)) {
		*wc_buffer.b64++ = ntohll(cqe64->timestamp);
		wc_flags_out |= IBV_WC_EX_WITH_COMPLETION_TIMESTAMP;
	}

	switch (opcode) {
	case MLX5_CQE_REQ:
		err = mlx5_poll_one_cqe_req(cq, cur_rsc, cqe, qpn, cqe_ver,
					    &wc_ex->wr_id);
		handle_good_req_ex(wc_ex, &wc_buffer, cqe64, wc_flags,
				   wc_flags_yes, wc_flags_no, qpn,
				   &wc_flags_out);
		wc_ex->status = err;
		if (IS_IN_WC_FLAGS(wc_flags_yes, wc_flags_no, wc_flags,
				   IBV_WC_EX_WITH_SRC_QP))
			wc_buffer.b32++;
		if (IS_IN_WC_FLAGS(wc_flags_yes, wc_flags_no, wc_flags,
				   IBV_WC_EX_WITH_PKEY_INDEX))
			wc_buffer.b16++;
		if (IS_IN_WC_FLAGS(wc_flags_yes, wc_flags_no, wc_flags,
				   IBV_WC_EX_WITH_SLID))
			wc_buffer.b16++;
		if (IS_IN_WC_FLAGS(wc_flags_yes, wc_flags_no, wc_flags,
				   IBV_WC_EX_WITH_SL))
			wc_buffer.b8++;
		if (IS_IN_WC_FLAGS(wc_flags_yes, wc_flags_no, wc_flags,
				   IBV_WC_EX_WITH_DLID_PATH_BITS))
			wc_buffer.b8++;
		break;

	case MLX5_CQE_RESP_WR_IMM:
	case MLX5_CQE_RESP_SEND:
	case MLX5_CQE_RESP_SEND_IMM:
	case MLX5_CQE_RESP_SEND_INV: {
		uint8_t is_srq = 0;

		err = mlx5_poll_one_cqe_resp(mctx, cur_rsc, cur_srq, cqe64,
					     cqe_ver, qpn, &is_srq);
		if (unlikely(err))
			return CQ_POLL_ERR;

		wc_ex->status = handle_responder_ex(wc_ex, &wc_buffer, cqe64,
						    rsc_to_mqp(*cur_rsc),
						    is_srq ? *cur_srq : NULL,
						    wc_flags, wc_flags_yes,
						    wc_flags_no, qpn,
						    &wc_flags_out);
		break;
	}
	case MLX5_CQE_REQ_ERR:
	case MLX5_CQE_RESP_ERR:
		err = mlx5_poll_one_cqe_err(mctx, cur_rsc, cur_srq, cqe64,
					    cqe_ver, qpn, &wc_ex->status,
					    &wc_ex->vendor_err, &wc_ex->wr_id,
					    opcode);
		if (err != CQ_OK)
			return CQ_POLL_ERR;

	case MLX5_CQE_RESIZE_CQ:
		if (IS_IN_WC_FLAGS(wc_flags_yes, wc_flags_no, wc_flags,
				   IBV_WC_EX_WITH_BYTE_LEN))
			wc_buffer.b32++;
		if (IS_IN_WC_FLAGS(wc_flags_yes, wc_flags_no, wc_flags,
				   IBV_WC_EX_WITH_IMM))
			wc_buffer.b32++;
		if (IS_IN_WC_FLAGS(wc_flags_yes, wc_flags_no, wc_flags,
				   IBV_WC_EX_WITH_QP_NUM)) {
			*wc_buffer.b32++ = qpn;
			wc_flags_out |= IBV_WC_EX_WITH_QP_NUM;
		}
		if (IS_IN_WC_FLAGS(wc_flags_yes, wc_flags_no, wc_flags,
				   IBV_WC_EX_WITH_SRC_QP))
			wc_buffer.b32++;
		if (IS_IN_WC_FLAGS(wc_flags_yes, wc_flags_no, wc_flags,
				   IBV_WC_EX_WITH_PKEY_INDEX))
			wc_buffer.b16++;
		if (IS_IN_WC_FLAGS(wc_flags_yes, wc_flags_no, wc_flags,
				   IBV_WC_EX_WITH_SLID))
			wc_buffer.b16++;
		if (IS_IN_WC_FLAGS(wc_flags_yes, wc_flags_no, wc_flags,
				   IBV_WC_EX_WITH_SL))
			wc_buffer.b8++;
		if (IS_IN_WC_FLAGS(wc_flags_yes, wc_flags_no, wc_flags,
				   IBV_WC_EX_WITH_DLID_PATH_BITS))
			wc_buffer.b8++;
		break;
	}
	wc_ex->wc_flags = wc_flags_out;
	*pwc_ex = (struct ibv_wc_ex *)((uintptr_t)(wc_buffer.b8 + sizeof(uint64_t) - 1) &
				       ~(sizeof(uint64_t) - 1));
	return CQ_OK;
}

int mlx5_poll_one_ex(struct mlx5_cq *cq,
		     struct mlx5_resource **cur_rsc,
		     struct mlx5_srq **cur_srq,
		     struct ibv_wc_ex **pwc_ex, uint64_t wc_flags,
		     int cqe_ver)
{
	return _mlx5_poll_one_ex(cq, cur_rsc, cur_srq, pwc_ex, wc_flags, 0, 0,
				 cqe_ver);
}

#define MLX5_POLL_ONE_EX_WC_FLAGS_NAME(wc_flags_yes, wc_flags_no) \
	mlx5_poll_one_ex_custom##wc_flags_yes ## _ ## wc_flags_no

/* The compiler will create one function per wc_flags combination. Since
 * _mlx5_poll_one_ex  is always inlined (for compilers that supports that),
 * the compiler drops the if statements and merge all wc_flags_out ORs/ANDs.
 */
#define MLX5_POLL_ONE_EX_WC_FLAGS(wc_flags_yes, wc_flags_no)	\
static int MLX5_POLL_ONE_EX_WC_FLAGS_NAME(wc_flags_yes, wc_flags_no)		\
						(struct mlx5_cq *cq,		\
						 struct mlx5_resource **cur_rsc,\
						 struct mlx5_srq **cur_srq,	\
						 struct ibv_wc_ex **pwc_ex,	\
						 uint64_t wc_flags,		\
						 int cqe_ver)			\
{									        \
	return _mlx5_poll_one_ex(cq, cur_rsc, cur_srq, pwc_ex, wc_flags,        \
				 wc_flags_yes, wc_flags_no, cqe_ver);	        \
}

/*
	Since we use the preprocessor here, we have to calculate the Or value
	ourselves:
	IBV_WC_EX_GRH			= 1 << 0,
	IBV_WC_EX_IMM			= 1 << 1,
	IBV_WC_EX_WITH_BYTE_LEN		= 1 << 2,
	IBV_WC_EX_WITH_IMM		= 1 << 3,
	IBV_WC_EX_WITH_QP_NUM		= 1 << 4,
	IBV_WC_EX_WITH_SRC_QP		= 1 << 5,
	IBV_WC_EX_WITH_PKEY_INDEX	= 1 << 6,
	IBV_WC_EX_WITH_SLID		= 1 << 7,
	IBV_WC_EX_WITH_SL		= 1 << 8,
	IBV_WC_EX_WITH_DLID_PATH_BITS	= 1 << 9,
	IBV_WC_EX_WITH_COMPLETION_TIMESTAMP = 1 << 10,
*/

/* Bitwise or of all flags between IBV_WC_EX_WITH_BYTE_LEN and
 * IBV_WC_EX_WITH_COMPLETION_TIMESTAMP.
 */
#define SUPPORTED_WC_ALL_FLAGS	2045
/* Bitwise or of all flags between IBV_WC_EX_WITH_BYTE_LEN and
 * IBV_WC_EX_WITH_DLID_PATH_BITS (all the fields that are available
 * in the legacy WC).
 */
#define SUPPORTED_WC_STD_FLAGS  1020

#define OPTIMIZE_POLL_CQ	/* All maybe - must be in table! */	    \
				OP(0, 0)				SEP \
				/* No options */			    \
				OP(0, SUPPORTED_WC_ALL_FLAGS)		SEP \
				/* All options */			    \
				OP(SUPPORTED_WC_ALL_FLAGS, 0)		SEP \
				/* All standard options */		    \
				OP(SUPPORTED_WC_STD_FLAGS, 1024)	SEP \
				/* Just Bytelen - for DPDK */		    \
				OP(4, 1016)				SEP \
				/* Timestmap only, for FSI */		    \
				OP(1024, 1020)				SEP

#define OP	MLX5_POLL_ONE_EX_WC_FLAGS
#define SEP	;

/* Declare optimized poll_one function for popular scenarios. Each function
 * has a name of
 * mlx5_poll_one_ex_custom<supported_wc_flags>_<not_supported_wc_flags>.
 * Since the supported and not supported wc_flags are given beforehand,
 * the compiler could optimize the if and or statements and create optimized
 * code.
 */
OPTIMIZE_POLL_CQ

#define ADD_POLL_ONE(_wc_flags_yes, _wc_flags_no)			\
				{.wc_flags_yes = _wc_flags_yes,		\
				 .wc_flags_no = _wc_flags_no,		\
				 .fn = MLX5_POLL_ONE_EX_WC_FLAGS_NAME(  \
					_wc_flags_yes, _wc_flags_no)	\
				}

#undef OP
#undef SEP
#define OP	ADD_POLL_ONE
#define SEP	,

struct {
	int (*fn)(struct mlx5_cq *cq,
		  struct mlx5_resource **cur_rsc,
		  struct mlx5_srq **cur_srq,
		  struct ibv_wc_ex **pwc_ex, uint64_t wc_flags,
		  int cqe_ver);
	uint64_t wc_flags_yes;
	uint64_t wc_flags_no;
} mlx5_poll_one_ex_fns[] = {
	/* This array contains all the custom poll_one functions. Every entry
	 * in this array looks like:
	 * {.wc_flags_yes = <flags that are always in the wc>,
	 *  .wc_flags_no = <flags that are never in the wc>,
	 *  .fn = <the custom poll one function}.
	 * The .fn function is optimized according to the .wc_flags_yes and
	 * .wc_flags_no flags. Other flags have the "if statement".
	 */
	OPTIMIZE_POLL_CQ
};

/* This function gets wc_flags as an argument and returns a function pointer
 * of type  *	int (*fn)(struct mlx5_cq *cq,
		  struct mlx5_resource **cur_rsc,
		  struct mlx5_srq **cur_srq,
		  struct ibv_wc_ex **pwc_ex, uint64_t wc_flags,
		  int cqe_ver);
 * The returned function is one of the custom poll one functions declared in
 * mlx5_poll_one_ex_fns. The function is chosen as the function which the
 * number of wc_flags_maybe bits (the fields that aren't in the yes/no parts)
 * is the smallest.
 */
int (*mlx5_get_poll_one_fn(uint64_t wc_flags))(struct mlx5_cq *cq,
					       struct mlx5_resource **cur_rsc,
					       struct mlx5_srq **cur_srq,
					       struct ibv_wc_ex **pwc_ex, uint64_t wc_flags,
					       int cqe_ver)
{
	unsigned int i = 0;
	uint8_t min_bits = -1;
	int min_index = 0xff;

	for (i = 0;
	     i < sizeof(mlx5_poll_one_ex_fns) / sizeof(mlx5_poll_one_ex_fns[0]);
	     i++) {
		uint64_t bits;
		uint8_t nbits;

		/* Can't have required flags in "no" */
		if (wc_flags & mlx5_poll_one_ex_fns[i].wc_flags_no)
			continue;

		/* Can't have not required flags in yes */
		if (~wc_flags & mlx5_poll_one_ex_fns[i].wc_flags_yes)
			continue;

		/* Number of wc_flags_maybe. See above comment for more details */
		bits = (wc_flags  ^ mlx5_poll_one_ex_fns[i].wc_flags_yes) |
		       ((~wc_flags ^ mlx5_poll_one_ex_fns[i].wc_flags_no) &
			CREATE_CQ_SUPPORTED_WC_FLAGS);

		nbits = ibv_popcount64(bits);

		/* Look for the minimum number of bits */
		if (nbits < min_bits) {
			min_bits = nbits;
			min_index = i;
		}
	}

	assert(min_index >= 0);

	return mlx5_poll_one_ex_fns[min_index].fn;
}

static inline void mlx5_poll_cq_stall_start(struct mlx5_cq *cq)
ALWAYS_INLINE;
static inline void mlx5_poll_cq_stall_start(struct mlx5_cq *cq)
{
	if (cq->stall_enable) {
		if (cq->stall_adaptive_enable) {
			if (cq->stall_last_count)
				mlx5_stall_cycles_poll_cq(cq->stall_last_count + cq->stall_cycles);
		} else if (cq->stall_next_poll) {
			cq->stall_next_poll = 0;
			mlx5_stall_poll_cq();
		}
	}
}

static inline void mlx5_poll_cq_stall_end(struct mlx5_cq *cq, int ne,
					  int npolled, int err) ALWAYS_INLINE;
static inline void mlx5_poll_cq_stall_end(struct mlx5_cq *cq, int ne,
					  int npolled, int err)
{
	if (cq->stall_enable) {
		if (cq->stall_adaptive_enable) {
			if (npolled == 0) {
				cq->stall_cycles = max(cq->stall_cycles-mlx5_stall_cq_dec_step,
						       mlx5_stall_cq_poll_min);
				mlx5_get_cycles(&cq->stall_last_count);
			} else if (npolled < ne) {
				cq->stall_cycles = min(cq->stall_cycles+mlx5_stall_cq_inc_step,
						       mlx5_stall_cq_poll_max);
				mlx5_get_cycles(&cq->stall_last_count);
			} else {
				cq->stall_cycles = max(cq->stall_cycles-mlx5_stall_cq_dec_step,
						       mlx5_stall_cq_poll_min);
				cq->stall_last_count = 0;
			}
		} else if (err == CQ_EMPTY) {
			cq->stall_next_poll = 1;
		}
	}
}

static inline int poll_cq(struct ibv_cq *ibcq, int ne,
			  struct ibv_wc *wc, int cqe_ver)
	ALWAYS_INLINE;
static inline int poll_cq(struct ibv_cq *ibcq, int ne,
			  struct ibv_wc *wc, int cqe_ver)
{
	struct mlx5_cq *cq = to_mcq(ibcq);
	struct mlx5_resource *rsc = NULL;
	struct mlx5_srq *srq = NULL;
	int npolled;
	int err = CQ_OK;

	mlx5_poll_cq_stall_start(cq);
	mlx5_spin_lock(&cq->lock);

	for (npolled = 0; npolled < ne; ++npolled) {
		err = mlx5_poll_one(cq, &rsc, &srq, wc + npolled, cqe_ver);
		if (err != CQ_OK)
			break;
	}

	update_cons_index(cq);

	mlx5_spin_unlock(&cq->lock);

	mlx5_poll_cq_stall_end(cq, ne, npolled, err);

	return err == CQ_POLL_ERR ? err : npolled;
}

int mlx5_poll_cq(struct ibv_cq *ibcq, int ne, struct ibv_wc *wc)
{
	return poll_cq(ibcq, ne, wc, 0);
}

int mlx5_poll_cq_v1(struct ibv_cq *ibcq, int ne, struct ibv_wc *wc)
{
	return poll_cq(ibcq, ne, wc, 1);
}

static inline int poll_cq_ex(struct ibv_cq *ibcq, struct ibv_wc_ex *wc,
			     struct ibv_poll_cq_ex_attr *attr, int cqe_ver)
{
	struct mlx5_cq *cq = to_mcq(ibcq);
	struct mlx5_resource *rsc = NULL;
	struct mlx5_srq *srq = NULL;
	int npolled;
	int err = CQ_OK;
	int (*poll_fn)(struct mlx5_cq *cq, struct mlx5_resource **rsc,
		       struct mlx5_srq **cur_srq,
		       struct ibv_wc_ex **pwc_ex, uint64_t wc_flags,
		       int cqe_ver) =
		cq->poll_one;
	uint64_t wc_flags = cq->wc_flags;
	unsigned int ne = attr->max_entries;

	mlx5_poll_cq_stall_start(cq);
	mlx5_spin_lock(&cq->lock);

	for (npolled = 0; npolled < ne; ++npolled) {
		err = poll_fn(cq, &rsc, &srq, &wc, wc_flags, cqe_ver);
		if (err != CQ_OK)
			break;
	}

	update_cons_index(cq);

	mlx5_spin_unlock(&cq->lock);

	mlx5_poll_cq_stall_end(cq, ne, npolled, err);

	return err == CQ_POLL_ERR ? err : npolled;
}

int mlx5_poll_cq_ex(struct ibv_cq *ibcq, struct ibv_wc_ex *wc,
		    struct ibv_poll_cq_ex_attr *attr)
{
	return poll_cq_ex(ibcq, wc, attr, 0);
}

int mlx5_poll_cq_v1_ex(struct ibv_cq *ibcq, struct ibv_wc_ex *wc,
		       struct ibv_poll_cq_ex_attr *attr)
{
	return poll_cq_ex(ibcq, wc, attr, 1);
}

int mlx5_arm_cq(struct ibv_cq *ibvcq, int solicited)
{
	struct mlx5_cq *cq = to_mcq(ibvcq);
	struct mlx5_context *ctx = to_mctx(ibvcq->context);
	uint32_t doorbell[2];
	uint32_t sn;
	uint32_t ci;
	uint32_t cmd;

	sn  = cq->arm_sn & 3;
	ci  = cq->cons_index & 0xffffff;
	cmd = solicited ? MLX5_CQ_DB_REQ_NOT_SOL : MLX5_CQ_DB_REQ_NOT;

	cq->dbrec[MLX5_CQ_ARM_DB] = htonl(sn << 28 | cmd | ci);

	/*
	 * Make sure that the doorbell record in host memory is
	 * written before ringing the doorbell via PCI MMIO.
	 */
	wmb();

	doorbell[0] = htonl(sn << 28 | cmd | ci);
	doorbell[1] = htonl(cq->cqn);

	mlx5_write64(doorbell, ctx->uar[0] + MLX5_CQ_DOORBELL, &ctx->lock32);

	wc_wmb();

	return 0;
}

void mlx5_cq_event(struct ibv_cq *cq)
{
	to_mcq(cq)->arm_sn++;
}

static int is_equal_rsn(struct mlx5_cqe64 *cqe64, uint32_t rsn)
{
	return rsn == (ntohl(cqe64->sop_drop_qpn) & 0xffffff);
}

static inline int is_equal_uidx(struct mlx5_cqe64 *cqe64, uint32_t uidx)
{
	return uidx == (ntohl(cqe64->srqn_uidx) & 0xffffff);
}

static inline int is_responder(uint8_t opcode)
{
	switch (opcode) {
	case MLX5_CQE_RESP_WR_IMM:
	case MLX5_CQE_RESP_SEND:
	case MLX5_CQE_RESP_SEND_IMM:
	case MLX5_CQE_RESP_SEND_INV:
	case MLX5_CQE_RESP_ERR:
		return 1;
	}

	return 0;
}

static inline int free_res_cqe(struct mlx5_cqe64 *cqe64, uint32_t rsn,
			       struct mlx5_srq *srq, int cqe_version)
{
	if (cqe_version) {
		if (is_equal_uidx(cqe64, rsn)) {
			if (srq && is_responder(cqe64->op_own >> 4))
				mlx5_free_srq_wqe(srq,
						  ntohs(cqe64->wqe_counter));
			return 1;
		}
	} else {
		if (is_equal_rsn(cqe64, rsn)) {
			if (srq && (ntohl(cqe64->srqn_uidx) & 0xffffff))
				mlx5_free_srq_wqe(srq,
						  ntohs(cqe64->wqe_counter));
			return 1;
		}
	}

	return 0;
}

void __mlx5_cq_clean(struct mlx5_cq *cq, uint32_t rsn, struct mlx5_srq *srq)
{
	uint32_t prod_index;
	int nfreed = 0;
	struct mlx5_cqe64 *cqe64, *dest64;
	void *cqe, *dest;
	uint8_t owner_bit;
	int cqe_version;

	if (!cq)
		return;

	/*
	 * First we need to find the current producer index, so we
	 * know where to start cleaning from.  It doesn't matter if HW
	 * adds new entries after this loop -- the QP we're worried
	 * about is already in RESET, so the new entries won't come
	 * from our QP and therefore don't need to be checked.
	 */
	for (prod_index = cq->cons_index; get_sw_cqe(cq, prod_index); ++prod_index)
		if (prod_index == cq->cons_index + cq->ibv_cq.cqe)
			break;

	/*
	 * Now sweep backwards through the CQ, removing CQ entries
	 * that match our QP by copying older entries on top of them.
	 */
	cqe_version = (to_mctx(cq->ibv_cq.context))->cqe_version;
	while ((int) --prod_index - (int) cq->cons_index >= 0) {
		cqe = get_cqe(cq, prod_index & cq->ibv_cq.cqe);
		cqe64 = (cq->cqe_sz == 64) ? cqe : cqe + 64;
		if (free_res_cqe(cqe64, rsn, srq, cqe_version)) {
			++nfreed;
		} else if (nfreed) {
			dest = get_cqe(cq, (prod_index + nfreed) & cq->ibv_cq.cqe);
			dest64 = (cq->cqe_sz == 64) ? dest : dest + 64;
			owner_bit = dest64->op_own & MLX5_CQE_OWNER_MASK;
			memcpy(dest, cqe, cq->cqe_sz);
			dest64->op_own = owner_bit |
				(dest64->op_own & ~MLX5_CQE_OWNER_MASK);
		}
	}

	if (nfreed) {
		cq->cons_index += nfreed;
		/*
		 * Make sure update of buffer contents is done before
		 * updating consumer index.
		 */
		wmb();
		update_cons_index(cq);
	}
}

void mlx5_cq_clean(struct mlx5_cq *cq, uint32_t qpn, struct mlx5_srq *srq)
{
	mlx5_spin_lock(&cq->lock);
	__mlx5_cq_clean(cq, qpn, srq);
	mlx5_spin_unlock(&cq->lock);
}

static uint8_t sw_ownership_bit(int n, int nent)
{
	return (n & nent) ? 1 : 0;
}

static int is_hw(uint8_t own, int n, int mask)
{
	return (own & MLX5_CQE_OWNER_MASK) ^ !!(n & (mask + 1));
}

void mlx5_cq_resize_copy_cqes(struct mlx5_cq *cq)
{
	struct mlx5_cqe64 *scqe64;
	struct mlx5_cqe64 *dcqe64;
	void *start_cqe;
	void *scqe;
	void *dcqe;
	int ssize;
	int dsize;
	int i;
	uint8_t sw_own;

	ssize = cq->cqe_sz;
	dsize = cq->resize_cqe_sz;

	i = cq->cons_index;
	scqe = get_buf_cqe(cq->active_buf, i & cq->active_cqes, ssize);
	scqe64 = ssize == 64 ? scqe : scqe + 64;
	start_cqe = scqe;
	if (is_hw(scqe64->op_own, i, cq->active_cqes)) {
		fprintf(stderr, "expected cqe in sw ownership\n");
		return;
	}

	while ((scqe64->op_own >> 4) != MLX5_CQE_RESIZE_CQ) {
		dcqe = get_buf_cqe(cq->resize_buf, (i + 1) & (cq->resize_cqes - 1), dsize);
		dcqe64 = dsize == 64 ? dcqe : dcqe + 64;
		sw_own = sw_ownership_bit(i + 1, cq->resize_cqes);
		memcpy(dcqe, scqe, ssize);
		dcqe64->op_own = (dcqe64->op_own & ~MLX5_CQE_OWNER_MASK) | sw_own;

		++i;
		scqe = get_buf_cqe(cq->active_buf, i & cq->active_cqes, ssize);
		scqe64 = ssize == 64 ? scqe : scqe + 64;
		if (is_hw(scqe64->op_own, i, cq->active_cqes)) {
			fprintf(stderr, "expected cqe in sw ownership\n");
			return;
		}

		if (scqe == start_cqe) {
			fprintf(stderr, "resize CQ failed to get resize CQE\n");
			return;
		}
	}
	++cq->cons_index;
}

int mlx5_alloc_cq_buf(struct mlx5_context *mctx, struct mlx5_cq *cq,
		      struct mlx5_buf *buf, int nent, int cqe_sz)
{
	struct mlx5_cqe64 *cqe;
	int i;
	struct mlx5_device *dev = to_mdev(mctx->ibv_ctx.device);
	int ret;
	enum mlx5_alloc_type type;
	enum mlx5_alloc_type default_type = MLX5_ALLOC_TYPE_ANON;

	if (mlx5_use_huge("HUGE_CQ"))
		default_type = MLX5_ALLOC_TYPE_HUGE;

	mlx5_get_alloc_type(MLX5_CQ_PREFIX, &type, default_type);

	ret = mlx5_alloc_prefered_buf(mctx, buf,
				      align(nent * cqe_sz, dev->page_size),
				      dev->page_size,
				      type,
				      MLX5_CQ_PREFIX);

	if (ret)
		return -1;

	memset(buf->buf, 0, nent * cqe_sz);

	for (i = 0; i < nent; ++i) {
		cqe = buf->buf + i * cqe_sz;
		cqe += cqe_sz == 128 ? 1 : 0;
		cqe->op_own = MLX5_CQE_INVALID << 4;
	}

	return 0;
}

int mlx5_free_cq_buf(struct mlx5_context *ctx, struct mlx5_buf *buf)
{
	return mlx5_free_actual_buf(ctx, buf);
}
