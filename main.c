/*
 * SNMP-Mikrotik
 *
 * read out connected RF-Clients on a Mikrotik Board and form a PHP-readable
 * string.
 *
 * Copyright (C) 2015 Hannes Schmelzer <oe5hpm@oevsv.at>
 *
 * SPDX-License-Identifier:	GPL-2.0+
 *
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#undef DEBUG		/* enable/disbale debug outputs */

#ifdef DEBUG
# define DBG(...)	printf(__VA_ARGS__)
#else
# define DBG(...)	;
#endif

#define PRERR(...)	fprintf(stderr, __VA_ARGS__)

#define ARREL(a)	(sizeof(a)/sizeof(a[0]))

struct client_t {
	unsigned char	macaddr[6];
	unsigned int	ifno;

	unsigned long	txbytes, rxbytes;
	char		tx[16], rx[16];
	unsigned int	txrate, rxrate;

	char		uptime[24];

	int		strength;
	int		tx0, tx1, rx0, rx1;

	struct client_t	*prev, *next;
};

struct client_t *attachclient(struct client_t *pclient)
{
	struct client_t *pnew = calloc(sizeof(struct client_t), 1);
	if (pnew == NULL)
		return NULL;

	if (pclient != NULL) {
		while (pclient->next != NULL) {
			pclient = pclient->next;
		};
		pclient->next = pnew;
		pnew->prev = pclient;
	}
	return pnew;
}

int querryclient(netsnmp_session *psess, struct client_t *pclient)
{
	int oidquerry[] = { 1, 3, 4, 5, 8, 9, 11, 13, 14, 15, 16, -1 };
	netsnmp_pdu *pdu;
	netsnmp_pdu *response;
	netsnmp_variable_list *vars;
	int status = -1;
	int i = 0;
	oid anOID[MAX_OID_LEN];
	size_t anOID_len;
	char buf[128];
	unsigned long tmp;
	float ftmp;
	const char du[][8] = { "byte", "kiB", "MiB", "GiB", "fail" };

	pdu = snmp_pdu_create(SNMP_MSG_GET);

	for (i=0; oidquerry[i] != -1; i++) {
		snprintf(buf, sizeof(buf),
			 ".1.3.6.1.4.1.14988.1.1.1.2.1.%d.%d.%d.%d.%d.%d.%d.%d",
			 oidquerry[i],
			 pclient->macaddr[0], pclient->macaddr[1],
			 pclient->macaddr[2], pclient->macaddr[3],
			 pclient->macaddr[4], pclient->macaddr[5],
			 pclient->ifno);
		anOID_len = MAX_OID_LEN;
		snmp_parse_oid(buf, anOID, &anOID_len);
		snmp_add_null_var(pdu, anOID, anOID_len);
	};
	status = snmp_synch_response(psess, pdu, &response);

	if (status != STAT_SUCCESS) {
		printf("something went wrong!\n");
		if (response)
			snmp_free_pdu(response);

		return status;
	}
	vars = response->variables;
	while (vars) {
//		print_variable(vars->name, vars->name_length, vars);
		snprint_objid(buf, sizeof(buf), vars->name, vars->name_length);

		if (strstr(buf, "14988.1.1.1.2.1.3."))
			pclient->strength = *vars->val.integer;
		if (strstr(buf, "14988.1.1.1.2.1.4.")) {
			pclient->txbytes = vars->val.counter64->high;
			ftmp = (float)vars->val.counter64->high;
			tmp = 0;
			while (ftmp > 1024) {
				ftmp /= 1024;
				tmp++;
			}
			snprintf(pclient->tx, sizeof(pclient->tx),
				"%.2f %s",
				ftmp,
				tmp < ARREL(du) ? du[tmp] : du[ARREL(du)-1]);
		}
		if (strstr(buf, "14988.1.1.1.2.1.5.")) {
			pclient->rxbytes = vars->val.counter64->high;
			ftmp = (float)vars->val.counter64->high;
			tmp = 0;
			while (ftmp > 1024) {
				ftmp /= 1024;
				tmp++;
			}
			snprintf(pclient->rx, sizeof(pclient->tx),
				"%.2f %s",
				ftmp,
				tmp < ARREL(du) ? du[tmp] : du[ARREL(du)-1]);
		}
		if (strstr(buf, "14988.1.1.1.2.1.8."))
			pclient->txrate = *vars->val.integer;
		if (strstr(buf, "14988.1.1.1.2.1.9."))
			pclient->rxrate = *vars->val.integer;
		if (strstr(buf, "14988.1.1.1.2.1.11.")) {
			unsigned int s, m, h, d;
			tmp = *vars->val.integer;
			tmp /= 100;
			s = tmp % 60;
			tmp = (tmp-s) / 60;
			m = tmp % 60;
			tmp = (tmp-m) / 60;
			h = tmp % 24;
			tmp = (tmp-h) / 24;
			d = tmp;

			snprintf(pclient->uptime, sizeof(pclient->uptime),
				 "%dd %dh %dm", d, h, m);
		}
		if (strstr(buf, "14988.1.1.1.2.1.13."))
			pclient->tx0 = *vars->val.integer;
		if (strstr(buf, "14988.1.1.1.2.1.14."))
			pclient->rx0 = *vars->val.integer;
		if (strstr(buf, "14988.1.1.1.2.1.15."))
			pclient->tx1 = *vars->val.integer;
		if (strstr(buf, "14988.1.1.1.2.1.16."))
			pclient->rx1 = *vars->val.integer;

		vars = vars->next_variable;
	}

	if (response)
		snmp_free_pdu(response);

	return status;
}

int main (int argc, char **argv)
{
	int i;

	char oidbuf[128];
	char phpbuf[512];

	netsnmp_session session, *ss;
	netsnmp_pdu *pdu;
	netsnmp_pdu *response;
	netsnmp_variable_list *vars;

	oid anOID[MAX_OID_LEN];
	size_t anOID_len;

	if (argc < 2) {
		printf("usage: %s <ip>\n", argv[0]);
		return -1;
	}

	int status;
	struct client_t *pclient = NULL;

	init_snmp(argv[0]);
	snmp_sess_init(&session);
	session.peername = strdup(argv[1]);
	session.version = SNMP_VERSION_1;
	session.community = "public";
	session.community_len = strlen(session.community);

	ss = snmp_open(&session);
	if (!ss) {
		snmp_sess_perror("ack", &session);
		exit(1);
	}

	strcpy(oidbuf, ".1.3.6.1.4.1.14988.1.1.1.2.1.1");

	while (1) {
		pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
		anOID_len = MAX_OID_LEN;
		snmp_parse_oid(oidbuf, anOID, &anOID_len);
		snmp_add_null_var(pdu, anOID, anOID_len);
		status = snmp_synch_response(ss, pdu, &response);

		if (status == STAT_SUCCESS) {
			vars = response->variables;
			if (vars->type == 4 && vars->val_len == 6) {
				snprint_objid(oidbuf, sizeof(oidbuf),
					      vars->name, vars->name_length);
				if (response)
					snmp_free_pdu(response);

				pclient = attachclient(pclient);
				memcpy(pclient->macaddr, vars->buf,
				       sizeof(pclient->macaddr));
				pclient->ifno = atoi(oidbuf + strlen(oidbuf)-1);
				querryclient(ss, pclient);
			} else {
				if (response)
					snmp_free_pdu(response);
				break;
			}
		} else {
			printf("timeout/error!\n");
			exit(1);
		}
	}

	struct client_t *tofree = NULL;
	do {
		tofree = pclient;
		snprintf(phpbuf, sizeof(phpbuf),
			"%02x-%02x-%02x-%02x-%02x-%02x;%s;%d;%d;%d;%d;%d;%lud;"\
			"%lud;%s;%s;%d;%d",
			pclient->macaddr[0], pclient->macaddr[1],
			pclient->macaddr[2], pclient->macaddr[3],
			pclient->macaddr[4], pclient->macaddr[5],
			pclient->uptime,
			pclient->strength,
			pclient->tx0, pclient->rx0,
			pclient->tx1, pclient->rx1,
			pclient->txbytes, pclient->rxbytes,
			pclient->tx, pclient->rx,
			pclient->txrate, pclient->rxrate
			);
		printf("%s\n", phpbuf);
		pclient = pclient->prev;
		free(tofree);
	} while (pclient);

	snmp_close(ss);

	return 0;
}
