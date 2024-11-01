/*
 * SPDX-License-Identifier: Apache-2.0
 */

#define LOG_MODULE_NAME net_lwm2m_obj_oscore
#define LOG_LEVEL CONFIG_LWM2M_LOG_LEVEL

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(LOG_MODULE_NAME);

#include <stdint.h>
#include <zephyr/init.h>

#include "lwm2m_object.h"
#include "lwm2m_engine.h"

#define OSCORE_VERSION_MAJOR 2
#define OSCORE_VERSION_MINOR 0

/* resource IDs */
#define OSCORE_MASTER_SECRET_RID		0
#define OSCORE_SENDER_ID_RID			1
#define OSCORE_RECIPIENT_ID_RID			2
#define OSCORE_AEAD_ALGORITHM_RID		3
#define OSCORE_HMAC_ALGORITHM_RID		4
#define OSCORE_MASTER_SALT_RID			5
#define OSCORE_ID_CONTEXT_RID			6

#define OSCORE_MAX_RID					7

#define MAX_INSTANCE_COUNT CONFIG_LWM2M_OSCORE_OBJ_INSTANCE_COUNT
#define RESOURCE_INSTANCE_COUNT	(OSCORE_MAX_RID)

#define MASTER_SECRET_SIZE CONFIG_LWM2M_OSCORE_OBJ_MASTER_SECRET_SIZE
#define SENDER_ID_SIZE CONFIG_LWM2M_OSCORE_OBJ_SENDER_ID_SIZE
#define RECIPIENT_ID_SIZE CONFIG_LWM2M_OSCORE_OBJ_RECIPIENT_ID_SIZE
#define MASTER_SALT_SIZE CONFIG_LWM2M_OSCORE_OBJ_MASTER_SALT_SIZE
#define ID_CONTEXT_SIZE CONFIG_LWM2M_OSCORE_OBJ_ID_CONTEXT_SIZE

/* resource state variables */
static uint8_t master_secret[MAX_INSTANCE_COUNT][MASTER_SECRET_SIZE];
static uint8_t sender_id[MAX_INSTANCE_COUNT][SENDER_ID_SIZE];
static uint8_t recipient_id[MAX_INSTANCE_COUNT][RECIPIENT_ID_SIZE];
static uint8_t aead_algorithm[MAX_INSTANCE_COUNT];
static uint8_t hmac_algorithm[MAX_INSTANCE_COUNT];
static uint8_t master_salt[MAX_INSTANCE_COUNT][MASTER_SALT_SIZE];
static uint8_t id_context[MAX_INSTANCE_COUNT][ID_CONTEXT_SIZE];

static struct lwm2m_engine_obj oscore;
static struct lwm2m_engine_obj_field fields[] = {
	OBJ_FIELD_DATA(OSCORE_MASTER_SECRET_RID, W, OPAQUE),
	OBJ_FIELD_DATA(OSCORE_SENDER_ID_RID, W, OPAQUE),
	OBJ_FIELD_DATA(OSCORE_RECIPIENT_ID_RID, W, OPAQUE),
	OBJ_FIELD_DATA(OSCORE_AEAD_ALGORITHM_RID, W_OPT, U8),
	OBJ_FIELD_DATA(OSCORE_HMAC_ALGORITHM_RID, W_OPT, U8),
	OBJ_FIELD_DATA(OSCORE_MASTER_SALT_RID, W_OPT, OPAQUE),
	OBJ_FIELD_DATA(OSCORE_ID_CONTEXT_RID, W_OPT, OPAQUE),
};

static struct lwm2m_engine_obj_inst inst[MAX_INSTANCE_COUNT];
static struct lwm2m_engine_res res[MAX_INSTANCE_COUNT][OSCORE_MAX_RID];
static struct lwm2m_engine_res_inst
			res_inst[MAX_INSTANCE_COUNT][RESOURCE_INSTANCE_COUNT];

static struct lwm2m_engine_obj_inst *oscore_create(uint16_t obj_inst_id)
{
	int index, i = 0, j = 0;

	/* Check that there is no other instance with this ID */
	for (index = 0; index < MAX_INSTANCE_COUNT; index++) {
		if (inst[index].obj && inst[index].obj_inst_id == obj_inst_id) {
			LOG_ERR("Can not create instance - "
				"already existing: %u", obj_inst_id);
			return NULL;
		}
	}

	for (index = 0; index < MAX_INSTANCE_COUNT; index++) {
		if (!inst[index].obj) {
			break;
		}
	}

	if (index >= MAX_INSTANCE_COUNT) {
		LOG_ERR("Can not create instance - "
			"no more room: %u", obj_inst_id);
		return NULL;
	}

	/* default values */
	master_secret[index][0] = '\0';
	sender_id[index][0] = '\0';
	recipient_id[index][0] = '\0';
	aead_algorithm[index] = 0U;
	hmac_algorithm[index] = 0U;
	master_salt[index][0] = '\0';
	id_context[index][0] = '\0';

	(void)memset(res[index], 0,
		     sizeof(res[index][0]) * ARRAY_SIZE(res[index]));
	init_res_instance(res_inst[index], ARRAY_SIZE(res_inst[index]));

	/* initialize instance resource data */
	INIT_OBJ_RES_DATA_LEN(OSCORE_MASTER_SECRET_RID, res[index], i,
			  res_inst[index], j,
			  &master_secret[index], MASTER_SECRET_SIZE, 0);
	INIT_OBJ_RES_DATA_LEN(OSCORE_SENDER_ID_RID, res[index], i,
			  res_inst[index], j,
			  &sender_id[index], SENDER_ID_SIZE, 0);
	INIT_OBJ_RES_DATA_LEN(OSCORE_RECIPIENT_ID_RID, res[index], i,
			  res_inst[index], j,
			  &recipient_id[index], RECIPIENT_ID_SIZE, 0);
	INIT_OBJ_RES_DATA(OSCORE_AEAD_ALGORITHM_RID, res[index], i,
			  res_inst[index], j,
			  &aead_algorithm[index], sizeof(*aead_algorithm));
	INIT_OBJ_RES_DATA(OSCORE_HMAC_ALGORITHM_RID, res[index], i,
			  res_inst[index], j,
			  &hmac_algorithm[index], sizeof(*hmac_algorithm));
	INIT_OBJ_RES_DATA_LEN(OSCORE_MASTER_SALT_RID, res[index], i,
			  res_inst[index], j,
			  &master_salt[index], MASTER_SALT_SIZE, 0);
	INIT_OBJ_RES_DATA_LEN(OSCORE_ID_CONTEXT_RID, res[index], i,
			  res_inst[index], j,
			  &id_context[index], ID_CONTEXT_SIZE, 0);

	inst[index].resources = res[index];
	inst[index].resource_count = i;
	LOG_DBG("Create LWM2M OSCORE instance: %d", obj_inst_id);

	return &inst[index];
}

static int lwm2m_oscore_init(void)
{
	struct lwm2m_engine_obj_inst *obj_inst = NULL;
	int ret = 0;

	oscore.obj_id = LWM2M_OBJECT_OSCORE_ID;
	oscore.version_major = OSCORE_VERSION_MAJOR;
	oscore.version_minor = OSCORE_VERSION_MINOR;
	oscore.is_core = true;
	oscore.fields = fields;
	oscore.field_count = ARRAY_SIZE(fields);
	oscore.max_instance_count = MAX_INSTANCE_COUNT;
	oscore.create_cb = oscore_create;
	lwm2m_register_obj(&oscore);

	/* auto create the first instance */
	ret = lwm2m_create_obj_inst(LWM2M_OBJECT_OSCORE_ID, 0, &obj_inst);
	if (ret < 0) {
		LOG_ERR("Create LWM2M OSCORE instance 0 error: %d", ret);
	}

	return ret;
}

LWM2M_CORE_INIT(lwm2m_oscore_init);
