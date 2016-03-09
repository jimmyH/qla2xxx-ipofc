/*
 * Program to display or modify configuration data for an executable.
 * In order for this to work, the main application or a library it contains
 * must have been built using the data structures provided by the
 * include file "configprog.h".
 *
 * Copyright (c) 2003 by David I. Bell.
 * Permission is granted to copy, distribute, modify, and use this source
 * file provided that this copyright notice remains intact.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <memory.h>
#include <string.h>
#define _GNU_SOURCE
#include <getopt.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>

#include "../qla_opts.h"


/*
 * Make a typedef for our convenience.
 */
typedef	config_entry_t	ENTRY;


/*
 * Boolean definitions.
 */
typedef	int	BOOL;

#define	TRUE	((BOOL) 1)
#define	FALSE	((BOOL) 0)


/*
 * Useful macros to examine table entries.
 */
#define	TO_ENTRY(cp)		((ENTRY *) (cp))
#define	TO_CONST_ENTRY(cp)	((const ENTRY *) (cp))
#define	TO_CP(entry)		((char *) (entry))
#define	NEXT_ENTRY(entry)	TO_ENTRY(TO_CP(entry) + (entry)->next)
#define	NEXT_CONST_ENTRY(entry)	TO_CONST_ENTRY(TO_CP(entry) + (entry)->next)
#define	IS_LAST(entry)		((entry)->next <= 0)
#define	IS_PADDING(entry)	(!IS_LAST(entry) && ((entry)->name[0] == '\0'))
#define	IS_ID(entry)		(!IS_LAST(entry) && (strcmp((entry)->name, CONFIG_ID_MAGIC) == 0))


/*
 * Sizes and other definitions.
 */
#define	DEFAULT_TABLE	"MAIN"
#define	VALUE_SIZE	sizeof(CONFIG_VALUE_MAGIC)
#define	NULL_ENTRY	((ENTRY *) 0)
#define	BUF_SIZE	sizeof(config_table_def_t) + NAME_SIZE  /* enough to read in whole config table */
#define	ALIGNMENT	4


/*
 * Structure which holds information about one of the configuration
 * tables found in the executable.  The table name is usually a
 * pointer into the table data, and so should not be freed.
 */
typedef	struct TABLE	TABLE;

struct	TABLE
{
	const char *	name;		/* name of this table */
	off_t		offset;		/* file offset of table */
	long		size;		/* size of the table */
	char *		data;		/* data for the table */
	TABLE *		nextTable;	/* next table in list */
};


void
qldbg_print(char *);
/*
 * Local function definitions.
 */
static	void	usage(int);
static	void	printValues(void);
static	void	setValues(void);
static	void	setTableValues(TABLE *);
static	void	printTableValues(const TABLE *);
static	void	openProgram(const char *, BOOL);
static	void	closeProgram(void);
static	TABLE *	getTable(const char *);
static	void	findTables(void);
static	void	readTable(TABLE *);
static	int	getTotalSpace(const TABLE *);
static	ENTRY *	findEntry(const TABLE *, const char *);
static	int	getEntrySize(const ENTRY *);
static	int	search(const char *, int);
static	void	fatalError(const char *);
static	void	systemError(const char *);


/*
 * Global variables.
 */
FILE *		dbghandle = NULL;
char		dbgstr[160];
static	int		fd;		/* opened file descriptor */
static	TABLE *		tableList;	/* linked list of configuration tables */
static	const char *	tableName;	/* configuration table name to process */

/*
 * Usage text for the program.
 * This array must be terminated by a null pointer.
 */
static	const char *	usageText[] =
{
	"",
	"qla_opts -- QLogic driver options utility -- v2",
	"",
	"Usage: qla_opts [OPTIONS]... MODULE",
	"",
	"Description:",
	"  Configure/Display QLogic Driver option information for a MODULE.",
	"",
	"  -f, --file=[FILE]",
	"        use module FILE for operations",
	"  -h, --help",
	"        display this help and exit",
	"  -p, --print",
	"        display option data embedded in a module",
	"  -v, --verbose",
	"        display extra debug information during operations",
	"  -w, --write",
	"        write option data to a module",
	"",
	"  MODULE must be 'qla2100_conf', 'qla2200_conf', 'qla2300_conf',",
	"   'qla200_conf', or 'qla2xxx_conf'.",
	"",
	"Option Data:",
	"  Option data is read from one of the following files depending on the",
	"  value of the MODULE parameter:",
	"",
	"        FILE               MODULE",
	"        -----------------  -------",
	"        /etc/qla2xxx.conf  qla2xxx_conf",
	"",
	"  By default, the following directory is used to specify the location of",
	"  the modules to update:", 
	"",
	"        /lib/modules/`uname -r`/kernel/drivers/scsi/qla2xxx",
	"",
	"  Where `uname -r` resolves to the release name of the currently running",
	"  kernel.",
	"",
	"  If a FILE is specified, MODULE instructs qla_opts to read option data ",
	"  from the appropriate configuration file.",
	"",
	"Examples:",
	"",
	"  Display option data for the default qla2xxx_conf module:",
	"",
	"        # qla_opts --print qla2xxx_conf",
	"",
	"  Write option data to the qla2xxx_conf module:",
	"",
	"        # qla_opts --write qla2xxx_conf",
	"",
	"  Write qla2xxx_conf type option data for a specified module:",
	"",
	"        # qla_opts --write --file=/usr/smith/driver/qla2xxx_conf.o qla2xxx_conf",
	"",
	0
};

#define OPT_PRINT	0
#define OPT_WRITE	1

#define MODULE_NONE		0
#define MODULE_QLA2XXX_CONF	5
struct module_info {

	char	*name;
	int	id;
	char	*conf_fname;

};
static struct module_info modules[] = {
	{ "qla2xxx_conf", MODULE_QLA2XXX_CONF, "/etc/qla2xxx.conf" },
	{ NULL, 0, NULL }
};
struct	module_info *module = NULL;

int	operation = OPT_PRINT;
int	verbose;
struct utsname uts_info;
char	def_module_path[PATH_MAX];
char	module_name[PATH_MAX] = { 0 };

int
main(int argc, char * const argv[])
{
	int	next_opt;
	const char	*short_opts = "f:hpvw";
	const struct option long_opts[] = {

		{ "file", 1, NULL, 'f' },
		{ "help", 0, NULL, 'h' },
		{ "print", 0, NULL, 'p' },
		{ "verbose", 0, NULL, 'v' },
		{ "write", 0, NULL, 'w' },
		{ NULL, 0, NULL, 0 }
	};
	struct	module_info *mod_iter;

	if (uname(&uts_info)) {
		fprintf(stderr, "***Unable to retrieve uname() system information...exiting!\n");
		exit(1);
	}

	/* Prepare update defaults */
	verbose = 0;
	sprintf(def_module_path, "/lib/modules/%s/kernel/drivers/scsi/qla2xxx",
	    uts_info.release);

	/* Scan through options */
	do {
		next_opt = getopt_long(argc, argv, short_opts, long_opts, NULL);
		switch (next_opt) {
		case 'f':
			/* Use alternate module
			 *
			 *   -f <module file> or --file=<module file>
			 */
			strcpy(module_name, optarg);
			break;

		case 'h':
			/* Display usage
			 *
			 *   -h or --help
			 */
			usage(0);
			break;

		case 'p':
			/* Display option information
			 *
			 *   -p or --print
			 */
			operation = OPT_PRINT;
			break;

		case 'v':
			/* Verbose operations
			 *
			 *   -v or --verbose
			 */
			verbose++;
			break;

		case 'w':
			/* Perform option write
			 *
			 *   -w or --write
			 */
			operation = OPT_WRITE;
			break;

		case '?':
			/* Invalid option */
			usage(1);
			break;

		case -1:
			/* Done with options */
			break;

		default:
			/* Something bad happened! */
			abort();
			break;
		}
	} while (next_opt != -1);

	/* Determine module */
	if (optind == argc) {
		printf("*** No MODULE specified!\n");
		usage(2);
	}
	module = NULL;
	for (mod_iter = modules; mod_iter->name; mod_iter++) {
		if (strcmp(argv[optind], mod_iter->name) == 0) {
			module = mod_iter;
			/* Default, if no module specified */
			if (!module_name[0])
				sprintf(module_name, "%s/%s.ko",
				    def_module_path, mod_iter->name);
			break;
		}
	}
	if (module == MODULE_NONE) {
		printf("*** Invalid MODULE specified (%s)!\n", argv[optind]);
		usage(3);
	}

	/* Determine operation */
	if (verbose)
		printf("Updating module: (%s)\n", module_name);

	if (operation == OPT_PRINT)
		printValues();
	else if (operation == OPT_WRITE)
		setValues();

	return 0;
}

void
qldbg_print(char *string)
{
	if (dbghandle) {
		 fprintf(dbghandle, string);
	}
}


/*
 * Print out the usage text and exit.
 */
static void
usage(int ret_code)
{
	const char **	cpp;

	for (cpp = usageText; *cpp; cpp++)
		fprintf(stdout, "%s\n", *cpp);

	exit(ret_code);
}


/*
 * Print out the configuration values in a program
 * for a table or all tables.
 */
static void
printValues(void)
{
	const TABLE *	table;

	openProgram(module_name, FALSE);

	if (tableName == 0)
	{
		if ((tableList == 0) && verbose)
		{
			printf("No configuration tables are present\n");

			return;
		}

		for (table = tableList; table; table = table->nextTable)
		{
			if (verbose && (table != tableList))
				printf("\n");

			printTableValues(table);
		}
	}
	else
	{
		table = getTable(tableName);

		printTableValues(table);
	}

	closeProgram();
}


/*
 * Set configuration values for one of the tables in a program.
 * Each value is of the form "name=value", where name must already
 * be present in the specified configuration table.
 */
static void
setValues(void)
{
	TABLE *	table;

	/*
	 * Open the program for writing.
	 */
	openProgram(module_name, TRUE);

	if (tableName == 0)
		tableName = module->name;

	table = getTable(tableName);

	setTableValues(table);

	closeProgram();
}


/*
 * Print the configuration values in the specified table.
 * This can be done in either brief or verbose format.
 */
static void
printTableValues(const TABLE * table)
{
	const ENTRY *	entry;
	int		totalSpace;
	const char *	format;

	format = "%s=%s\n";

	if (verbose)
	{
		format = "   %-16s %s\n";

		totalSpace = getTotalSpace(table);

		printf("Table \"%s\" (total %d bytes):\n",
			table->name, totalSpace);
	}

	entry = TO_CONST_ENTRY(table->data);
	entry = NEXT_CONST_ENTRY(entry);

	if (IS_ID(entry))
		entry = NEXT_CONST_ENTRY(entry);

	while (!IS_LAST(entry))
	{
		if (!IS_PADDING(entry)) {

			printf(format, entry->name, entry->value);
		}

		entry = NEXT_CONST_ENTRY(entry);
	}

}


/*
 * Set configuration values for the specified table in a program.
 * Each value is of the form "name=value", where name must already
 * be present in the specified configuration table.
 */
static void
setTableValues(TABLE * table)
{
	ENTRY *		entry;		/* current entry */
	int		cc;		/* amount of data written */

	FILE	*conf_file;
	int	cnt;
	struct stat conf_stats;
	int	mod_max_size;
	int	data_size;
	char	*conf_data;


	conf_file = fopen(module->conf_fname, "r");
	if (conf_file == NULL) {
		fprintf(stderr,
		    "qla_opts: unable to load conf file (%s)!!!\n",
		    module->conf_fname);

		exit(1);
	}

	if (verbose)
		printf("Using conf file: (%s)\n", module->conf_fname);

	/* Determine max size to read */
	mod_max_size = getTotalSpace(table);
	fstat(fileno(conf_file), &conf_stats);
	data_size = conf_stats.st_size;
	if (conf_stats.st_size > mod_max_size) {
		fprintf(stderr,
		    "qla_opts: reduce conf file size --  (max=%d)!!!\n",
		    mod_max_size);

		exit(1);
	}

	conf_data = malloc(data_size+1);
	conf_data[data_size] = 0;
	cnt = fread(conf_data, sizeof(char), data_size, conf_file);
	if (cnt != data_size) {
		fprintf(stderr,
		    "qla_opts: unable to read conf data!!!\n");
		free(conf_data);

		exit(1);
	}
	fclose(conf_file);

	if (verbose)
		printf("Read %d (%s)\n", cnt, conf_data);

	readTable(table);

	/*
	 * Find the configuration entry with that name.
	 */
	entry = findEntry(table, "OPTIONS");
	if (entry == NULL_ENTRY) {
		fprintf(stderr,
			"%s: configuration name \"%s\" undefined\n",
			module_name, "OPTIONS");
		free(conf_data);

		exit(1);
	}

	/*
	 * Make sure the new value will fit, and then copy the
	 * new value into the table.
	 */
	if ((entry->value + strlen(conf_data)) >=
	    (TO_CP(entry) + entry->next)) {
		free(conf_data);
		fatalError("Insufficient room in table for specified "
		    "config values");
	}

	strcpy(entry->value, conf_data);

	free(conf_data);

	/*
	 * All new values have been set, now write back out the table.
	 */

	if (lseek(fd, table->offset, 0) < 0)
		systemError("lseek");

	cc = write(fd, table->data, table->size);

	if (cc < 0)
		systemError("write");

	if (cc != table->size)
		fatalError("Short write");

	if (verbose)
		printf("Successful update...\n");
}


/*
 * Find the entry corresponding to the specifed name.
 * Returns a pointer to the found configuration entry, or
 * NULL_ENTRY if there is no entry with that name.
 */
static ENTRY *
findEntry(const TABLE * table, const char * entryName)
{
	ENTRY *	entry;

	entry = TO_ENTRY(table->data);
	entry = NEXT_ENTRY(entry);

	while (!IS_LAST(entry))
	{
		if (strcmp(entry->name, entryName) == 0)
			return entry;

		entry = NEXT_ENTRY(entry);
	}

	return NULL_ENTRY;
}


/*
 * Return the actual size of an entry based on its configuration value.
 * The size is rounded up to the next multiple of ALIGNMENT bytes.
 */
static int
getEntrySize(const ENTRY * entry)
{
	int	valueSize;	/* space used by config value */
	int	entrySize;	/* space used by whole entry */

	valueSize = strlen(entry->value) + 1;

	entrySize = CONFIG_NAME_SIZE + sizeof(int) + sizeof(int) + valueSize;

	if (entrySize % ALIGNMENT)
		entrySize += ALIGNMENT - (entrySize % ALIGNMENT);

	return entrySize;
}

/*
 * Find out the amount of total space in the configuration table.
 */
static int
getTotalSpace(const TABLE * table)
{
	const ENTRY *	entry;
	int		totalSpace;

	entry = TO_CONST_ENTRY(table->data);

	totalSpace = entry->next;

	entry = NEXT_CONST_ENTRY(entry);

	while (!IS_LAST(entry))
	{
		totalSpace += entry->next;

		entry = NEXT_CONST_ENTRY(entry);
	}

	return totalSpace;
}

/*
 * Return information about the specified table name.
 * Exits if the table is not present or is duplicated.
 */
static TABLE *
getTable(const char * tableName)
{
	TABLE *	table;
	TABLE *	foundTable;

	foundTable = 0;

	for (table = tableList; table; table = table->nextTable)
	{
		if (strcmp(table->name, tableName) == 0)
		{
			if (foundTable)
			{
				fprintf(stderr,
				    "%s: Duplicate configuration "
				    "table \"%s\"\n",
				    module_name, tableName);

				exit(1);
			}

			foundTable = table;
		}
	}

	if (foundTable == 0)
	{
		fprintf(stderr,
			"%s: Configuration table \"%s\" does not exist\n",
			module_name, tableName);

		exit(1);
	}

	/*
	 * Return the unique table.
	 */
	return foundTable;
}


/*
 * Search an opened file for the offsets of all of the configuration
 * tables in the opened file, and read those tables into memory.
 * The tricky part is handling strings which cross buffer boundaries.
 */
static void
findTables(void)
{
	TABLE *		table;		/* table entry */
	const char *	data;		/* data left to examine in buffer */
	int		dataSize;	/* amount of data left to examine */
	int		cc;		/* amount of data read */
	int		searchIndex;	/* index of found string */
	off_t		currentOffset;	/* current file position */
	off_t		tableOffset;	/* position of table */
	char		*buffer;
	BOOL		found = FALSE;

	currentOffset = 0;
	buffer = malloc(BUF_SIZE + NAME_SIZE);
	if (buffer == NULL)
		fatalError("Memory allocation failed");
	memset(buffer, 0, NAME_SIZE);

	/*
	 * Read data from the file a buffer at a time and search it.
	 * Keep copying the last bit of data from the end of the previous
	 * buffer to the beginning of the next buffer so that the magic
	 * string value can be found even across buffer boundaries.
	 */
	while ((cc = read(fd, buffer + NAME_SIZE, BUF_SIZE)) > 0)
	{
		data = buffer;
		dataSize = cc + NAME_SIZE;

		while ((searchIndex = search(data, dataSize)) >= 0)
		{
			table = (TABLE *) malloc(sizeof(TABLE));

			if (table == 0)
				fatalError("Memory allocation failed");

			tableOffset = currentOffset + (data - buffer) +
				searchIndex - NAME_SIZE;

			table->name = "";
			table->offset = tableOffset;
			table->size = 0;
			table->nextTable = tableList;

			tableList = table;

			data += (searchIndex + NAME_SIZE);
			dataSize -= (searchIndex + NAME_SIZE);

			found = TRUE;
			break;
		}
		if (found)
			break;

		memcpy(buffer, buffer + BUF_SIZE, NAME_SIZE);

		currentOffset += cc;
	}

	free(buffer);
	if (cc < 0)
		systemError("read");
}


/*
 * Read in the complete table data for the specified table given
 * its beginning offset.
 */
static void
readTable(TABLE * table)
{
	const ENTRY *	entry;		/* current config entry */
	char *		data;		/* current table data */
	int		dataSize;	/* current table data size */
	int		maxSize;	/* current max size of table */
	int		growSize;	/* amount to grow table by */
	int		cc;		/* amount read */

	/*
	 * Allocate the initial buffer which will be reallocated as needed.
	 */
	maxSize = BUF_SIZE;

	data = malloc(BUF_SIZE);
	if (data == 0)
		fatalError("Cannot allocate table");

	/*
	 * Seek to the correct position and read the first bit of the table.
	 * If the end of the file is reached early, then zero the buffer
	 * and an error will be detected later.
	 */
	if (lseek(fd, table->offset, 0) < 0)
		systemError("lseek");

	cc = read(fd, data, BUF_SIZE);

	if (cc < 0)
		systemError("read");

	if (cc < BUF_SIZE)
		memset(data + cc, 0, BUF_SIZE - cc);

	/*
	 * Verify more completely that this is really a valid table.
	 */
	entry = TO_ENTRY(data);

	if (memcmp(entry->name, CONFIG_NAME_MAGIC, NAME_SIZE))
		fatalError("Bad table magic name");

	if (memcmp(entry->value, CONFIG_VALUE_MAGIC, VALUE_SIZE))
		fatalError("Bad table magic value");

	if (entry->next <= NAME_SIZE + VALUE_SIZE)
		fatalError("Bad next value or variable in table");

	/*
	 * Walk through the configuration table entries and check them
	 * slightly, while keeping track of the total length, and reading
	 * more of the file if necessary.
	 */
	dataSize = 0;
	while (!IS_LAST(entry))
	{
		if (getEntrySize(entry) > entry->next)
			fatalError("Bad offset to next value");

		dataSize += entry->next;

		entry = NEXT_ENTRY(entry);
		growSize = dataSize + entry->next - maxSize;

		if (growSize <= 0)
			continue;

		/*
		 * Getting near the end of our array.
		 * Grow it some more and read in the next bit of the table.
		 * Be sure to reposition the structure pointer since the
		 * table may have moved.
		 */
		growSize += (BUF_SIZE - growSize % BUF_SIZE);

		data = realloc(data, maxSize + growSize);

		if (data == 0)
			fatalError("Cannot reallocate table");

		entry = TO_ENTRY(data + maxSize);

		cc = read(fd, data + maxSize, growSize);

		if (cc < 0)
			systemError("read");

		if (cc < growSize)
			memset(data + maxSize + cc, 0, growSize - cc);

		maxSize += growSize;
	}

	/*
	 * Verify that the end of the table looks reasonable.
	 */
	if (strcmp(entry->name, CONFIG_END_NAME) ||
	    entry->value[0])
		fatalError("Bad end of table");

	/*
	 * Save the table information.
	 */
	table->data = data;
	table->size = dataSize;

	/*
	 * Find and save the table name if it is present.
	 * This can only be done when we are done reading the table since
	 * the table name is a pointer into the table data buffer.
	 */
	entry = TO_ENTRY(data);
	entry = NEXT_ENTRY(entry);

	if (IS_ID(entry))
		table->name = entry->value;
	else
		table->name = "unknown";
}


/*
 * Open the specified module_name for reading or writing, and read in all
 * of the configuration tables found in the program so that they can
 * be examined or updated.
 */
static void
openProgram(const char * module_name, BOOL writeFlag)
{
	TABLE *	table;
	int	openMode;

	/*
	 * Open the file for reading or writing as specified.
	 */
	openMode = (writeFlag ? O_RDWR : O_RDONLY);

	fd = open(module_name, openMode);

	if (fd < 0)
		systemError("open");

	/*
	 * Find all of the tables in the program.
	 */
	findTables();

	/*
	 * Read in all of the tables.
	 */
	for (table = tableList; table; table = table->nextTable)
		readTable(table);
}



/*
 * Close the program if necessary.
 * Doesn't return on an error.
 */
static void
closeProgram(void)
{
	TABLE *	table;
	TABLE *	nexttable;

	if ((fd >= 0) && (close(fd) < 0))
		systemError("close");

	for (table = tableList; table; table = nexttable) {
		nexttable = table->nextTable;
		free(table);
	}
}


/*
 * Search the specified buffer for the first instance of the magic
 * CONFIG_NAME_MAGIC string.  Returns the index into the buffer of
 * the string, or -1 if it was not found.
 */
static int
search(const char * buffer, int bufferSize)
{
	const char *	data;		/* current location in buffer */
	const char *	oldData;	/* previous location in buffer */

	data = buffer;
	oldData = buffer;
	bufferSize -= NAME_SIZE;

	while (bufferSize > 0)
	{
		data = memchr(oldData, CONFIG_NAME_MAGIC[0], bufferSize);

		if (data == NULL)
			return -1;

		/*
		 * Poking at internal layouts of structures in pre-compiled
		 * module binaries is hacky at best.  Compensate for varied
		 * layouts by 'strengthening' the match to require the followup
		 * size field to be equal to the config_s_entry_t size and the
		 * 'reserved' field to be 0.
		 */
		if ((data[1] == CONFIG_NAME_MAGIC[1]) &&
		    (memcmp(data, CONFIG_NAME_MAGIC, NAME_SIZE) == 0) &&
		    *((int *)&data[NAME_SIZE]) == sizeof(config_s_entry_t) &&
		    *((int *)&data[NAME_SIZE+sizeof(int)]) == 0)
			return (data - buffer);

		bufferSize -= (data - oldData) + 1;
		oldData = data + 1;
	}

	return -1;
}


/*
 * Complain about something being wrong and exit.
 */
static void
fatalError(const char * msg)
{
	fprintf(stderr, "%s: %s\n", module_name, msg);

	exit(1);
}


/*
 * Complain about an operating system error and exit.
 */
static void
systemError(const char * msg)
{
	fprintf(stderr, "%s: ", module_name);
	perror(msg);

	exit(1);
}

/* END CODE */
