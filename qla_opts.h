/* qla_opts.h
 *
 * Persistent binding structures.
 *
 * Original copyright notice below:
 *
 */

/*
 * Include file for defining configuration variables.
 *
 * Configuration variables are pairs of strings, similar to getenv.
 * Using this file allows the configuration information in the actual
 * executable file to be modified later by running the configprog program.
 * This avoids having to rebuild the program in order to change the
 * default string values such as path names, which can be very useful.
 *
 * Configuration variable names which do not begin with a period are
 * also looked up using getenv, so that the user can override these
 * default values.
 *
 * Configuration variable names beginning with a period cannot be
 * overridden by getenv and thus are good for critical definitions.
 * The maximum configuration variable name size is 16 characters.
 * The maximum configuration variable value size is set at compile time
 * by CONFIG_SIZE.  But when running configprog, some of the
 * configuration variable values can be made longer since all config
 * variables share the same buffer.
 *
 * There can be multiple configuration tables within one executable.
 * Each one is identified by a unique table name.  This allows each
 * library used within a program to have its own configuration table.
 * The main program itself uses a table name of "main".
 *
 * This file includes <stdlib.h> in order to define getenv.
 *
 * Copyright (c) 2003 by David I. Bell
 * Permission is granted to copy, distribute, modify, and use this source
 * file provided that this copyright notice remains intact.
 */

#ifndef	QLA_OPTS_H
#define	QLA_OPTS_H


/*
 * The version of the configuration program that handles us.
 */
#define	CONFIG_VERSION	"QLA_OPTS 2.0"


#ifndef __KERNEL__
/*
 * We need the definition of getenv.
 */
#include <stdlib.h>
#endif

/*
 * The maximum size of a configuration variable value at compile time.
 * This can be changed by defining CONFIG_SIZE before including this file.
 * For backward compatibility with the configuration utilities the maximum
 * working value is 10 times of the value provided in the first distribution
 * -- 300000.
 */
#ifndef	CONFIG_SIZE
#define	CONFIG_SIZE	300000
#endif


/*
 * The maximum size of a configuration variable name.
 * This must not be changed since configprog can't handle multiple sizes.
 */
#define	CONFIG_NAME_SIZE	16

#define SHORT_ENT_SIZE		40
#define CFG_ITEM_SIZE		CONFIG_SIZE

/*
 * One entry in the configuration variable table.
 * At compile time all entries must be the same size since they are defined
 * in an array.  But the configprog program is able to shuffle the elements
 * around, so later on the entries will have different sizes (the 'value'
 * field can change size).
 */
typedef struct	_config_s_entry_
{
	char	name[CONFIG_NAME_SIZE];	/* name of configuration variable */
	int	next;			/* offset to next entry */
	int	reserved;
	char	value[SHORT_ENT_SIZE];	/* value of begin/end entries */
} config_s_entry_t;

typedef struct	_config_entry_
{
	char	name[CONFIG_NAME_SIZE];	/* name of configuration variable */
	int	next;			/* offset to next entry */
	int	reserved;
	char	value[CFG_ITEM_SIZE];	/* value of configuration variable */
} config_entry_t;

typedef config_entry_t config_l_entry_t;

typedef struct _config_table_def_
{
	config_s_entry_t	name_st;
	config_s_entry_t	id_st;
	config_l_entry_t	item1_st;
	config_s_entry_t	end_st;
} config_table_def_t;

/*
 * Special strings used to begin and end the configuration table.
 * These are obscure so that there is minimal chance that random data
 * in the executable will match these.
 */
#define	CONFIG_NAME_MAGIC	"\007<CoNfIg\007NaMe>\007"
#define	CONFIG_VALUE_MAGIC	"\007<cOnFiG\007vAlUe>\007"
#define	CONFIG_ID_MAGIC		"\007<cOnFiG\007iD>\007"
#define	CONFIG_END_NAME		"\007<EnD\007cOnFiG>\007"

#define NAME_SIZE       sizeof(CONFIG_NAME_MAGIC)
#define ID_SIZE      	sizeof(CONFIG_ID_MAGIC)


/*
 * Macros to build the configuration table.
 *	CONFIG_BEGIN		begins the named configuration table
 *	CONFIG_ITEM		defines one configuration variable
 *	CONFIG_END		ends the configuration table
 */
#define	CONFIG_BEGIN(id) \
	static config_table_def_t _config_table_ = \
	{ \
		{ \
			CONFIG_NAME_MAGIC, sizeof(config_s_entry_t), \
			0, CONFIG_VALUE_MAGIC \
		}, \
		{ \
			CONFIG_ID_MAGIC, sizeof(config_s_entry_t), \
			0, (id) \
		},

#define	CONFIG_ITEM(name, value) \
		{ \
			(name), sizeof(config_l_entry_t), \
			0, (value) \
		},

#define	CONFIG_END \
		{ \
			CONFIG_END_NAME, 0, 0, "" \
		} \
	};

/*
 * Macro to do the configuration.
 * This must be executed for each file which defines a configuration table.
 * If a valid config item is found, it sets the specified pointer to the
 * specified value.  Note: the supposedly useless do statement
 * makes this macro usable in an IF THEN ELSE statement.
 */
#define	QLOPTS_CONFIGURE(qla_persistent_str) \
	do { \
		config_entry_t *_config_ep_; \
		_config_ep_ = (config_entry_t *)&_config_table_; \
		for (;;) { \
			_config_ep_ = (config_entry_t *) \
				(((char *) _config_ep_) + _config_ep_->next); \
			if (_config_ep_->next == 0) \
				break; \
			if (memcmp(_config_ep_->name, CONFIG_NAME_MAGIC,\
					       	NAME_SIZE) == 0 || \
			    memcmp(_config_ep_->name, CONFIG_ID_MAGIC,\
				    ID_SIZE) == 0)\
				continue; \
			qla_persistent_str = _config_ep_->value; \
			if (_config_ep_->value[0] == '\0') \
				memset(_config_ep_->value, '\0', CFG_ITEM_SIZE); \
		} \
	} while (0)

#endif

/* END CODE */
