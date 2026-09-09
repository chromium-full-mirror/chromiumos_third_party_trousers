
/*
 * Licensed Materials - Property of IBM
 *
 * trousers - An open source TCG Software Stack
 *
 * (C) Copyright International Business Machines Corp. 2004-2006
 *
 */

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <limits.h>

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "trousers_types.h"
#include "spi_utils.h"
#include "capabilities.h"
#include "tsplog.h"
#include "hosttable.h"
#include "tcsd_wrap.h"
#include "obj.h"
#include "rpc_tcstp_tsp.h"
#include "tsp_tcsi_param.h"

#include "libhwsec-foundation/tpm_error/tpm_error_data.h"
#include "libhwsec-foundation/tpm_error/tpm_error_uma_report.h"

void
initData(struct tcsd_comm_data *comm, int parm_count)
{
	/* min packet size should be the size of the header */
	__tspi_memset(&comm->hdr, 0, sizeof(struct tcsd_packet_hdr));
	comm->hdr.packet_size = sizeof(struct tcsd_packet_hdr);
	comm->hdr.type_offset = sizeof(struct tcsd_packet_hdr);
	comm->hdr.parm_offset = comm->hdr.type_offset + (sizeof(TCSD_PACKET_TYPE) * parm_count);
	comm->hdr.packet_size = comm->hdr.parm_offset;

	__tspi_memset(comm->buf, 0, comm->buf_size);
}

int
loadData(UINT64 *offset, TCSD_PACKET_TYPE data_type, void *data, int data_size, BYTE *blob)
{
	switch (data_type) {
		case TCSD_PACKET_TYPE_BYTE:
			Trspi_LoadBlob_BYTE(offset, *((BYTE *) (data)), blob);
			break;
		case TCSD_PACKET_TYPE_BOOL:
			Trspi_LoadBlob_BOOL(offset, *((TSS_BOOL *) (data)), blob);
			break;
		case TCSD_PACKET_TYPE_UINT16:
			Trspi_LoadBlob_UINT16(offset, *((UINT16 *) (data)), blob);
			break;
		case TCSD_PACKET_TYPE_UINT32:
			Trspi_LoadBlob_UINT32(offset, *((UINT32 *) (data)), blob);
			break;
		case TCSD_PACKET_TYPE_PBYTE:
			Trspi_LoadBlob(offset, data_size, blob, (BYTE *)data);
			break;
		case TCSD_PACKET_TYPE_NONCE:
			Trspi_LoadBlob(offset, 20, blob, ((TCPA_NONCE *)data)->nonce);
			break;
		case TCSD_PACKET_TYPE_DIGEST:
			Trspi_LoadBlob(offset, 20, blob, ((TCPA_DIGEST *)data)->digest);
			break;
		case TCSD_PACKET_TYPE_AUTH:
			LoadBlob_AUTH(offset, blob, ((TPM_AUTH *)data));
			break;
		case TCSD_PACKET_TYPE_UUID:
			Trspi_LoadBlob_UUID(offset, blob, *((TSS_UUID *)data));
			break;
		case TCSD_PACKET_TYPE_ENCAUTH:
			Trspi_LoadBlob(offset, 20, blob, ((TCPA_ENCAUTH *)data)->authdata);
			break;
		case TCSD_PACKET_TYPE_VERSION:
			Trspi_LoadBlob_TCPA_VERSION(offset, blob, *((TCPA_VERSION *)data));
			break;
#ifdef TSS_BUILD_PS
		case TCSD_PACKET_TYPE_LOADKEY_INFO:
			LoadBlob_LOADKEY_INFO(offset, blob, ((TCS_LOADKEY_INFO *)data));
			break;
#endif
		case TCSD_PACKET_TYPE_PCR_EVENT:
			Trspi_LoadBlob_PCR_EVENT(offset, blob, ((TSS_PCR_EVENT *)data));
			break;
		case TCSD_PACKET_TYPE_COUNTER_VALUE:
			Trspi_LoadBlob_COUNTER_VALUE(offset, blob, ((TPM_COUNTER_VALUE *)data));
			break;
		case TCSD_PACKET_TYPE_SECRET:
			Trspi_LoadBlob(offset, 20, blob, ((TCPA_SECRET *)data)->authdata);
			break;
		default:
			LogError("TCSD packet type unknown! (0x%x)", data_type & 0xff);
			return TSPERR(TSS_E_INTERNAL_ERROR);
	}

	return TSS_SUCCESS;
}

int
setData(TCSD_PACKET_TYPE dataType,
	int index,
	void *theData,
	int theDataSize,
	struct tcsd_comm_data *comm)
{
        UINT64 old_offset, offset;
        TSS_RESULT result;
        TCSD_PACKET_TYPE *type;

        /* Calculate the size of the area needed (use NULL for blob address) */
        offset = 0;
        if ((result = loadData(&offset, dataType, theData, theDataSize, NULL)))
                return result;
        if ((comm->hdr.packet_size + offset) > TSS_TPM_TXBLOB_SIZE) {
                LogError("Too much data to be transmitted!");
                return TSPERR(TSS_E_INTERNAL_ERROR);
        }
        if ((comm->hdr.packet_size + offset) > comm->buf_size) {
                /* reallocate the buffer */
                BYTE *buffer;
                int buffer_size = comm->hdr.packet_size + offset;

                LogDebug("Increasing communication buffer to %d bytes.", buffer_size);
                buffer = realloc(comm->buf, buffer_size);
                if (buffer == NULL) {
                        LogError("realloc of %d bytes failed.", buffer_size);
                        return TSPERR(TSS_E_INTERNAL_ERROR);
                }
                comm->buf_size = buffer_size;
                comm->buf = buffer;
        }

        offset = old_offset = comm->hdr.parm_offset + comm->hdr.parm_size;
        if ((result = loadData(&offset, dataType, theData, theDataSize, comm->buf)))
                return result;
        type = (TCSD_PACKET_TYPE *)(comm->buf + comm->hdr.type_offset) + index;
        *type = dataType;
        comm->hdr.type_size += sizeof(TCSD_PACKET_TYPE);
        comm->hdr.parm_size += (offset - old_offset);

        comm->hdr.packet_size = offset;
        comm->hdr.num_parms++;

        return TSS_SUCCESS;
}

UINT32
getData(TCSD_PACKET_TYPE dataType,
	int index,
	void *theData,
	int theDataSize,
	struct tcsd_comm_data *comm)
{
	TSS_RESULT result;
	UINT64 old_offset, offset;
	UINT64 limit;
	TCSD_PACKET_TYPE *type;

	/* The header was decoded straight off the wire in sendTCSDPacket();
	 * clamp every offset against the bytes that were actually received
	 * before dereferencing comm->buf. packet_size <= buf_size is enforced
	 * by send_init()/tcs_sendit(); packet_size is what was actually read. */
	if (!comm || !comm->buf || index < 0)
		return TSS_TCP_RPC_BAD_PACKET_TYPE;

	limit = comm->hdr.packet_size;
	if (limit > comm->buf_size)
		limit = comm->buf_size;

	if ((UINT64)comm->hdr.type_offset > limit ||
	    (UINT64)comm->hdr.type_size > limit - (UINT64)comm->hdr.type_offset ||
	    /* Note: type_size is an element count here because
	     * sizeof(TCSD_PACKET_TYPE) == 1 (BYTE in rpc_tcstp.h). */
	    (UINT32)index >= comm->hdr.type_size ||
	    (UINT32)index >= comm->hdr.num_parms) {
		LogDebug("type_offset/type_size/index out of range");
		return TSS_TCP_RPC_BAD_PACKET_TYPE;
	}
	type = (TCSD_PACKET_TYPE *)(comm->buf + comm->hdr.type_offset) + index;

	if (dataType != *type) {
		LogDebug("Data type of TCS packet element %d doesn't match.", index);
		return TSS_TCP_RPC_BAD_PACKET_TYPE;
	}
	old_offset = offset = comm->hdr.parm_offset;
	if (old_offset > limit) {
		LogDebug("parm_offset out of range");
		return TSS_TCP_RPC_BAD_PACKET_TYPE;
	}
	UINT64 rem_cap = limit - old_offset;
	if (rem_cap > (UINT64)comm->hdr.parm_size)
		rem_cap = (UINT64)comm->hdr.parm_size;

	switch (dataType) {
		case TCSD_PACKET_TYPE_BYTE:
			if (sizeof(BYTE) > rem_cap)
				return TSS_TCP_RPC_BAD_PACKET_TYPE;
			Trspi_UnloadBlob_BYTE(&offset, (BYTE *)theData, comm->buf);
			break;
		case TCSD_PACKET_TYPE_BOOL:
			if (sizeof(TSS_BOOL) > rem_cap)
				return TSS_TCP_RPC_BAD_PACKET_TYPE;
			Trspi_UnloadBlob_BOOL(&offset, (TSS_BOOL *)theData, comm->buf);
			break;
		case TCSD_PACKET_TYPE_UINT16:
			if (sizeof(UINT16) > rem_cap)
				return TSS_TCP_RPC_BAD_PACKET_TYPE;
			Trspi_UnloadBlob_UINT16(&offset, (UINT16 *)theData, comm->buf);
			break;
		case TCSD_PACKET_TYPE_UINT32:
			if (sizeof(UINT32) > rem_cap)
				return TSS_TCP_RPC_BAD_PACKET_TYPE;
			Trspi_UnloadBlob_UINT32(&offset, (UINT32 *)theData, comm->buf);
			break;
		case TCSD_PACKET_TYPE_UINT64:
			if (sizeof(UINT64) > rem_cap)
				return TSS_TCP_RPC_BAD_PACKET_TYPE;
			Trspi_UnloadBlob_UINT64(&offset, (UINT64 *)theData, comm->buf);
			break;
		case TCSD_PACKET_TYPE_PBYTE:
			if (theDataSize < 0 || (UINT64)theDataSize > rem_cap)
				return TSS_TCP_RPC_BAD_PACKET_TYPE;
			Trspi_UnloadBlob(&offset, theDataSize, comm->buf, (BYTE *)theData);
			break;
		case TCSD_PACKET_TYPE_NONCE:
			if (sizeof(TPM_NONCE) > rem_cap)
				return TSS_TCP_RPC_BAD_PACKET_TYPE;
			Trspi_UnloadBlob_NONCE(&offset, comm->buf, (TPM_NONCE *)theData);
			break;
		case TCSD_PACKET_TYPE_DIGEST:
			if (sizeof(TCPA_DIGEST) > rem_cap)
				return TSS_TCP_RPC_BAD_PACKET_TYPE;
			Trspi_UnloadBlob(&offset, sizeof(TCPA_DIGEST), comm->buf,
					 theData ? ((TCPA_DIGEST *)theData)->digest : NULL);
			break;
		case TCSD_PACKET_TYPE_AUTH:
			if (sizeof(TPM_NONCE) + sizeof(TSS_BOOL) + sizeof(TPM_AUTHDATA) > rem_cap)
				return TSS_TCP_RPC_BAD_PACKET_TYPE;
			UnloadBlob_AUTH(&offset, comm->buf, ((TPM_AUTH *)theData));
			break;
		case TCSD_PACKET_TYPE_UUID:
			if (sizeof(TSS_UUID) > rem_cap)
				return TSS_TCP_RPC_BAD_PACKET_TYPE;
			Trspi_UnloadBlob_UUID(&offset, comm->buf, ((TSS_UUID *)theData));
			break;
		case TCSD_PACKET_TYPE_ENCAUTH:
			if (sizeof(TCPA_ENCAUTH) > rem_cap)
				return TSS_TCP_RPC_BAD_PACKET_TYPE;
			Trspi_UnloadBlob(&offset, sizeof(TCPA_ENCAUTH), comm->buf,
					 theData ? ((TCPA_ENCAUTH *)theData)->authdata : NULL);
			break;
		case TCSD_PACKET_TYPE_VERSION:
			if (sizeof(TCPA_VERSION) > rem_cap)
				return TSS_TCP_RPC_BAD_PACKET_TYPE;
			Trspi_UnloadBlob_TCPA_VERSION(&offset, comm->buf,
						      ((TCPA_VERSION *)theData));
			break;
		case TCSD_PACKET_TYPE_KM_KEYINFO: {
			/* Fixed prefix: TSS_VERSION(4) + UUID(16) + UUID(16) + BYTE(1) + BOOL(1) + UINT32(4) = 42 */
			UINT32 vlen;
			if (42 > rem_cap)
				return TSS_TCP_RPC_BAD_PACKET_TYPE;
			vlen = Decode_UINT32(&comm->buf[old_offset + 38]);
			if ((UINT64)vlen > rem_cap - 42)
				return TSS_TCP_RPC_BAD_PACKET_TYPE;
			if ((result = Trspi_UnloadBlob_KM_KEYINFO(&offset, comm->buf,
								  ((TSS_KM_KEYINFO *)theData))))
				return result;
			break;
		}
		case TCSD_PACKET_TYPE_KM_KEYINFO2: {
			/* Fixed prefix: TSS_VERSION(4) + UUID(16) + UUID(16) + BYTE(1) +
			 * UINT32(4) + UINT32(4) + BOOL(1) + UINT32(4) = 50 */
			UINT32 vlen;
			if (50 > rem_cap)
				return TSS_TCP_RPC_BAD_PACKET_TYPE;
			vlen = Decode_UINT32(&comm->buf[old_offset + 46]);
			if ((UINT64)vlen > rem_cap - 50)
				return TSS_TCP_RPC_BAD_PACKET_TYPE;
			if ((result = Trspi_UnloadBlob_KM_KEYINFO2(&offset, comm->buf,
								   ((TSS_KM_KEYINFO2 *)theData))))
				return result;
			break;
		}
#ifdef TSS_BUILD_PS
		case TCSD_PACKET_TYPE_LOADKEY_INFO:
			/* Fixed size: UUID(16) + UUID(16) + Digest(20) + AuthHandle(4) +
			 * Nonce(20) + Nonce(20) + BOOL(1) + HMAC(20) = 117 */
			if (117 > rem_cap)
				return TSS_TCP_RPC_BAD_PACKET_TYPE;
			UnloadBlob_LOADKEY_INFO(&offset, comm->buf, ((TCS_LOADKEY_INFO *)theData));
			break;
#endif
		case TCSD_PACKET_TYPE_PCR_EVENT: {
			/* Fixed prefix: TCPA_VERSION(4) + ulPcrIndex(4) + eventType(4) +
			 * ulPcrValueLength(4) + ulEventLength(4) = 20 */
			UINT32 pcr_len, event_len;
			if (20 > rem_cap)
				return TSS_TCP_RPC_BAD_PACKET_TYPE;
			pcr_len = Decode_UINT32(&comm->buf[old_offset + 12]);
			if ((UINT64)pcr_len > rem_cap - 20)
				return TSS_TCP_RPC_BAD_PACKET_TYPE;
			event_len = Decode_UINT32(&comm->buf[old_offset + 16 + pcr_len]);
			if ((UINT64)event_len > rem_cap - 20 - (UINT64)pcr_len)
				return TSS_TCP_RPC_BAD_PACKET_TYPE;
			if ((result = Trspi_UnloadBlob_PCR_EVENT(&offset, comm->buf,
								 ((TSS_PCR_EVENT *)theData))))
				return result;
			break;
		}
		case TCSD_PACKET_TYPE_COUNTER_VALUE:
			if (sizeof(TPM_STRUCTURE_TAG) + 4 + sizeof(UINT32) > rem_cap)
				return TSS_TCP_RPC_BAD_PACKET_TYPE;
			Trspi_UnloadBlob_COUNTER_VALUE(&offset, comm->buf,
						       ((TPM_COUNTER_VALUE *)theData));
			break;
		case TCSD_PACKET_TYPE_SECRET:
			if (sizeof(TCPA_SECRET) > rem_cap)
				return TSS_TCP_RPC_BAD_PACKET_TYPE;
			Trspi_UnloadBlob(&offset, sizeof(TCPA_SECRET), comm->buf,
					 theData ? ((TCPA_SECRET *)theData)->authdata : NULL);
			break;
		default:
			LogError("unknown data type (%d) in TCSD packet!", dataType);
			return -1;
	}
	UINT64 consumed = offset - old_offset;
	if (consumed > (UINT64)comm->hdr.parm_size) {
		LogDebug("parameter consumed (%llu) exceeds parm_size (%u)",
			 (unsigned long long)consumed, comm->hdr.parm_size);
		return TSS_TCP_RPC_BAD_PACKET_TYPE;
	}
	comm->hdr.parm_offset = offset;
	comm->hdr.parm_size -= (UINT32)consumed;

	return TSS_SUCCESS;
}

TSS_RESULT
sendTCSDPacket(struct host_table_entry *hte)
{
	TSS_RESULT rc;
	UINT64 offset = 0;
	UINT32 ordinal = 0;

#ifdef MOCK_TPM
	/*
	 * If there's no real TPM just return failure right away.  The rest
	 * of the system will deal with it.
	 */
	return TSPERR(TSS_E_COMM_FAILURE);
#endif

	Trspi_LoadBlob_UINT32(&offset, hte->comm.hdr.packet_size, hte->comm.buf);
	Trspi_LoadBlob_UINT32(&offset, hte->comm.hdr.u.ordinal, hte->comm.buf);
	Trspi_LoadBlob_UINT32(&offset, hte->comm.hdr.num_parms, hte->comm.buf);
	Trspi_LoadBlob_UINT32(&offset, hte->comm.hdr.type_size, hte->comm.buf);
	Trspi_LoadBlob_UINT32(&offset, hte->comm.hdr.type_offset, hte->comm.buf);
	Trspi_LoadBlob_UINT32(&offset, hte->comm.hdr.parm_size, hte->comm.buf);
	Trspi_LoadBlob_UINT32(&offset, hte->comm.hdr.parm_offset, hte->comm.buf);
	ordinal = hte->comm.hdr.u.ordinal;

#if 0
	/* ---  Send it */
	printBuffer(hte->comm.buf, hte->comm.hdr.packet_size);
	LogInfo("Sending Packet with TCSD ordinal 0x%X", hte->comm.hdr.u.ordinal);
#endif
	/* if the ordinal is open context, there are some host table entry
	 * manipulations that must be done, so call _init
	 */
	if (ordinal == TCSD_ORD_OPENCONTEXT) {
		if ((rc = send_init(hte))) {
			report_metrics(ordinal, rc);
			LogError("Failed to send packet");
			return rc;
		}
	} else {
		if ((rc = tcs_sendit(hte))) {
			report_metrics(ordinal, rc);
			LogError("Failed to send packet");
			return rc;
		}
	}

	/* create a platform version of the tcsd header */
	offset = 0;
	Trspi_UnloadBlob_UINT32(&offset, &hte->comm.hdr.packet_size, hte->comm.buf);
	Trspi_UnloadBlob_UINT32(&offset, &hte->comm.hdr.u.result, hte->comm.buf);
	Trspi_UnloadBlob_UINT32(&offset, &hte->comm.hdr.num_parms, hte->comm.buf);
	Trspi_UnloadBlob_UINT32(&offset, &hte->comm.hdr.type_size, hte->comm.buf);
	Trspi_UnloadBlob_UINT32(&offset, &hte->comm.hdr.type_offset, hte->comm.buf);
	Trspi_UnloadBlob_UINT32(&offset, &hte->comm.hdr.parm_size, hte->comm.buf);
	Trspi_UnloadBlob_UINT32(&offset, &hte->comm.hdr.parm_offset, hte->comm.buf);

	report_metrics(ordinal, hte->comm.hdr.u.result);
	return TSS_SUCCESS;
}

int
recv_from_socket(int sock, void *buffer, int size)
{
	int recv_size = 0, recv_total = 0;

	while (recv_total < size) {
		errno = 0;
		if ((recv_size = recv(sock, buffer+recv_total, size-recv_total, 0)) <= 0) {
			if (recv_size < 0) {
				if (errno == EINTR)
					continue;
				LogError("Socket receive connection error: %s.", strerror(errno));
			} else {
				LogDebug("Socket connection closed.");
			}

			return -1;
		}
		recv_total += recv_size;
	}

	return recv_total;
}

int
send_to_socket(int sock, void *buffer, int size)
{
	int send_size = 0, send_total = 0;

	while (send_total < size) {
		if ((send_size = send(sock, buffer+send_total, size-send_total, 0)) < 0) {
			LogError("Socket send connection error: %s.", strerror(errno));
			return -1;
		}
		send_total += send_size;
	}

	return send_total;
}

TSS_RESULT
send_init(struct host_table_entry *hte)
{
	int sd = -1;
	int recv_size;
	BYTE *buffer;
	TSS_RESULT result;

	result = get_socket(hte, &sd);
	if (result != TSS_SUCCESS)
		goto err_exit;

	if (send_to_socket(sd, hte->comm.buf, hte->comm.hdr.packet_size) < 0) {
		result = TSPERR(TSS_E_COMM_FAILURE);
		goto err_exit;
	}

	buffer = hte->comm.buf;
	recv_size = sizeof(struct tcsd_packet_hdr);
	if (recv_from_socket(sd, buffer, recv_size) < 0) {
		result = TSPERR(TSS_E_COMM_FAILURE);
		goto err_exit;
	}
	buffer += sizeof(struct tcsd_packet_hdr);       /* increment the receive buffer pointer */

	/* check the packet size */
	recv_size = Decode_UINT32(hte->comm.buf);
	if (recv_size < (int)sizeof(struct tcsd_packet_hdr)) {
		LogError("Packet to receive from socket %d is too small (%d bytes)",
				sd, recv_size);
		result = TSPERR(TSS_E_COMM_FAILURE);
		goto err_exit;
	}

	if (recv_size > (int) hte->comm.buf_size ) {
		BYTE *new_buffer;

		LogDebug("Increasing communication buffer to %d bytes.", recv_size);
		new_buffer = realloc(hte->comm.buf, recv_size);
		if (new_buffer == NULL) {
			LogError("realloc of %d bytes failed.", recv_size);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto err_exit;
		}
		buffer = new_buffer + sizeof(struct tcsd_packet_hdr);
		hte->comm.buf_size = recv_size;
		hte->comm.buf = new_buffer;
	}

	/* get the rest of the packet */
	recv_size -= sizeof(struct tcsd_packet_hdr);    /* already received the header */
	if (recv_from_socket(sd, buffer, recv_size) < 0) {
		result = TSPERR(TSS_E_COMM_FAILURE);
		goto err_exit;
	}

	hte->socket = sd;

	return TSS_SUCCESS;

err_exit:
	if (sd != -1)
		close(sd);
	return result;
}

TSS_RESULT
tcs_sendit(struct host_table_entry *hte)
{
	int recv_size;
	BYTE *buffer;
	TSS_RESULT result;

	if (send_to_socket(hte->socket, hte->comm.buf, hte->comm.hdr.packet_size) < 0) {
		result = TSPERR(TSS_E_COMM_FAILURE);
		goto err_exit;
	}

	buffer = hte->comm.buf;
	recv_size = sizeof(struct tcsd_packet_hdr);
	if ((recv_size = recv_from_socket(hte->socket, buffer, recv_size)) < 0) {
		result = TSPERR(TSS_E_COMM_FAILURE);
		goto err_exit;
	}
	buffer += recv_size;            /* increment the receive buffer pointer */

	/* check the packet size */
	recv_size = Decode_UINT32(hte->comm.buf);
	if (recv_size < (int)sizeof(struct tcsd_packet_hdr)) {
		LogError("Packet to receive from socket %d is too small (%d bytes)",
				hte->socket, recv_size);
		result = TSPERR(TSS_E_COMM_FAILURE);
		goto err_exit;
	}

	if (recv_size > (int) hte->comm.buf_size ) {
		BYTE *new_buffer;

		LogDebug("Increasing communication buffer to %d bytes.", recv_size);
		new_buffer = realloc(hte->comm.buf, recv_size);
		if (new_buffer == NULL) {
			LogError("realloc of %d bytes failed.", recv_size);
			result = TSPERR(TSS_E_OUTOFMEMORY);
			goto err_exit;
		}
		buffer = new_buffer + sizeof(struct tcsd_packet_hdr);
		hte->comm.buf_size = recv_size;
		hte->comm.buf = new_buffer;
	}

	/* get the rest of the packet */
	recv_size -= sizeof(struct tcsd_packet_hdr);    /* already received the header */
	if ((recv_size = recv_from_socket(hte->socket, buffer, recv_size)) < 0) {
		result = TSPERR(TSS_E_COMM_FAILURE);
		goto err_exit;
	}

	return TSS_SUCCESS;

err_exit:
	return result;
}

TSS_RESULT
get_unix_socket(int *sd)
{
	int tmp_sd;
	struct sockaddr_un addr;

	tmp_sd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (tmp_sd == -1) {
		LogWarn("Failed unix socket: %s", strerror(errno));
		goto err_exit;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, TCSD_UNIX_SOCKET);

	if (connect(tmp_sd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
		LogWarn("Failed unix connect: %s - %s", addr.sun_path, strerror(errno));
		goto err_exit;
	}

	*sd = tmp_sd;
	return TSS_SUCCESS;

err_exit:
	if (tmp_sd != -1)
		close(tmp_sd);
	return TSPERR(TSS_E_CONNECTION_FAILED);
}

/* TODO: Future work - remove socket creation/manipulation from RPC-specific file */
TSS_RESULT
get_socket(struct host_table_entry *hte, int *sd)
{
	char port_str[TCP_PORT_STR_MAX_LEN]; // To accomodate string 65535
	struct addrinfo hints, *p, *res=NULL;
	int rv;
	TSS_RESULT result = TSS_SUCCESS;

	if (strcmp((char*)hte->hostname, TSS_LOCALHOST_STRING) == 0) {
		// If a unix socket is enabled, use it.
		if (get_unix_socket(sd) == TSS_SUCCESS) {
			goto exit;
		}
	}
	__tspi_memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICSERV;

	__tspi_memset(&port_str, 0, sizeof(port_str));

	if (get_tcsd_port(port_str) != TSS_SUCCESS) {
		LogError("Could not retrieve TCP port information.");
		goto exit;
	}

	LogDebug("Retrieving address information from host: %s", (char *)hte->hostname);
	rv = getaddrinfo((char *)hte->hostname, port_str,
			&hints, &res);
	if (rv != 0) {
		LogError("hostname %s does not resolve to a valid address.", hte->hostname);
		result = TSPERR(TSS_E_CONNECTION_FAILED);
		res = NULL;
		goto exit;
	}

	LogWarn("Got a list of valid IPs");

	for (p = res; p != NULL; p = p->ai_next) {

		*sd = socket(p->ai_family, SOCK_STREAM, 0);
		if (*sd == -1)
			continue;

		if (connect(*sd, p->ai_addr, p->ai_addrlen) != -1)
			break; // Got a connection

		LogWarn("Could not connect to machine: %s", (char*)hte->hostname);

		close(*sd);
		*sd = -1;
	}

	if (p == NULL) {
		LogError("Could not connect to any machine in the list.");
		result = TSPERR(TSS_E_COMM_FAILURE);
		goto exit;
	}

exit:
	if (res != NULL)
		freeaddrinfo(res);

	return result;
}

void
report_metrics(UINT32 ordinal, UINT32 response) {
	if (ordinal > TCSD_LAST_ORD) {
		LogWarn("The ordinal (%d) is invalid.", ordinal);
	}
	// Mask out everything but layer and error code.
	response &= 0xFFFF;

	struct TpmErrorData data = {ordinal, response};
	if (!ReportTpm1CommandAndResponse(&data)) {
		LogError("Failed to report tpm1 command and reponse");
	}
}
