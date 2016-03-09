extern void inter_module_register(const char *,
                struct module *, const void *);
extern void inter_module_unregister(const char *);
extern const void * inter_module_get(const char *);
extern const void * inter_module_get_request(const char *,
                const char *);
extern void inter_module_put(const char *);
