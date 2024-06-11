#ifndef __OFONO_SIM_SWITCH_H
#define __OFONO_SIM_SWITCH_H

#ifdef __cplusplus
extern "C" {
#endif

#include <ofono/types.h>

#define ACTIA_PRO_ACTIVE_CARD_SLOT   "ActiveCardSlot"
#define ACTIA_PRO_CARD_SLOT_COUNT    "CardSlotCount"

struct ofono_sim_switch;
struct ofono_modem;

typedef void (*ofono_sim_switch_set_active_card_slot_cb_t)(
					const struct ofono_error *error,
					void *data);

struct ofono_sim_switch_driver {
	const char *name;
	int (*probe)(struct ofono_sim_switch *sm, unsigned int vendor, void *data);
	void (*remove)(struct ofono_sim_switch *sm);
	void (*set_active_card_slot)(struct ofono_sim_switch *sm, unsigned int index,
			ofono_sim_switch_set_active_card_slot_cb_t cb, void *data);
};

int ofono_sim_switch_driver_register(const struct ofono_sim_switch_driver *d);
void ofono_sim_switch_driver_unregister(const struct ofono_sim_switch_driver *d);

struct ofono_sim_switch *ofono_sim_switch_create(struct ofono_modem *modem,
                                                 unsigned int vendor,
                                                 const char *driver, void *data);

void ofono_sim_switch_register(struct ofono_sim_switch *sm);
void ofono_sim_switch_remove(struct ofono_sim_switch *sm);

void ofono_sim_switch_set_data(struct ofono_sim_switch *sm, void *data);
void *ofono_sim_switch_get_data(struct ofono_sim_switch *sm);

void ofono_sim_switch_set_card_slot_count(struct ofono_sim_switch *sm, unsigned int val);
void ofono_sim_switch_set_active_card_slot(struct ofono_sim_switch *sm, unsigned int val);

#ifdef __cplusplus
}
#endif

#endif /* __OFONO_SIM_SWITCH_H */
