// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file replaces `rpc.c` when fuzzing is enabled.
// The replaced `getData()` fucntion provides fuzzed data for upper layers of
// the trousers client. In the trousers client, data come from the tcsd will be
// parsed by `getData()`, so injecting `getData()` is a way to provide fuzzed
// tcsd data. An instinct alternative is to inject `recv_from_socket` instead,
// but we choose `getData()` because `getData()` provides structured data, which
// allows the fuzzer getting a higher coverage faster.

#include "trousers/tss.h"
#include "trousers/trousers.h"
#include "trousers_types.h"
#include "capabilities.h"
#include "tsplog.h"
#include "hosttable.h"
#include "tcsd_wrap.h"

#include "libhwsec-foundation/fuzzed_trousers_utils.h"


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
setData(TCSD_PACKET_TYPE dataType,
	int index,
	void *theData,
	int theDataSize,
	struct tcsd_comm_data *comm)
{
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

	switch (dataType) {
		case TCSD_PACKET_TYPE_BYTE:
			*(BYTE *)theData = FuzzedTrousersConsumeByte();
			break;
		case TCSD_PACKET_TYPE_BOOL:
			*(TSS_BOOL *)theData = FuzzedTrousersConsumeBool();
			break;
		case TCSD_PACKET_TYPE_UINT16:
			*(UINT16 *)theData = FuzzedTrousersConsumeUint16();
			break;
		case TCSD_PACKET_TYPE_UINT32:
			*(UINT32 *)theData = FuzzedTrousersConsumeUint32();
			break;
		case TCSD_PACKET_TYPE_UINT64:
			*(UINT64 *)theData = FuzzedTrousersConsumeUint64();
			break;
		case TCSD_PACKET_TYPE_PBYTE:
			FuzzedTrousersConsumeBytes(theDataSize, theData);
			break;
		case TCSD_PACKET_TYPE_NONCE:
			if (theData) {
				FuzzedTrousersConsumeBytes(TPM_SHA1_160_HASH_LEN, ((TPM_NONCE *)theData)->nonce);
			}
			break;
		case TCSD_PACKET_TYPE_DIGEST:
			FuzzedTrousersConsumeBytes(sizeof(TCPA_DIGEST), ((TCPA_DIGEST *)theData)->digest);
			break;
		case TCSD_PACKET_TYPE_AUTH:
		case TCSD_PACKET_TYPE_UUID:
		case TCSD_PACKET_TYPE_ENCAUTH:
		case TCSD_PACKET_TYPE_VERSION:
		case TCSD_PACKET_TYPE_KM_KEYINFO:
		case TCSD_PACKET_TYPE_KM_KEYINFO2:
#ifdef TSS_BUILD_PS
		case TCSD_PACKET_TYPE_LOADKEY_INFO:
#endif
		case TCSD_PACKET_TYPE_PCR_EVENT:
		case TCSD_PACKET_TYPE_COUNTER_VALUE:
		case TCSD_PACKET_TYPE_SECRET:
			// TODO(domen): Support these data types.
			LogError("fuzzer unsupported data type (%d) in TCSD packet", dataType);
			return -1;
		default:
			LogError("unknown data type (%d) in TCSD packet!", dataType);
			return -1;
	}

	return TSS_SUCCESS;
}

TSS_RESULT
sendTCSDPacket(struct host_table_entry *hte)
{
	// TODO(domen): Make it possible to return an error.
	hte->comm.hdr.u.result = 0;
	return TSS_SUCCESS;
}
