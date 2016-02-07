# libanchor
OSX routine hooking w/ Mach exception handlers.


A serious `README` will come soon, for now _libanchor_ is still in a primitive state, so it makes no sense writing a detailed `README` for something that will change soon.

I have to give a big shoutout to [qwertyoruiop]("https://twitter.com/qwertyoruiop"), who originally suggested this hooking approach a long time ago, which only recently I have experimented with.

## Usage
Here are the basic APIs:

-   `uint16_t __anchor_init(void)`: Initializes _libanchor_, by registering an exception port for the current task and spawning the listener thread.
-   `void __anchor_set_hook(void *original, void *hook)`: Sets an hook in function `original` to function `hook`. `original` mustn't be already hooked.
-   `void __anchor_unset_hook(void *original)`: Unsets the hook from function `original`. `original` must be hooked.

## Examples
Hooking a simple local function:

```
void hook(void) {
    printf("hook!\n");
}

void test(void) {
    printf("test() here!\n");
}

int main(void) {

    if (__anchor_init() == ANCHOR_INIT_FAILURE)
        return -1;

    test();
    __anchor_set_hook(test, hook);
    test();

    return 0;
}
```

Hooking a function with arguments:

```
int hook(const char *s) {
    printf("hook!\n");

    hook_table_entry_t *p=NULL;
    HOOK_TABLE_HOOK_LOOKUP(get_hook_table_head(), hook, p);

    __anchor_unset_hook(p->__original);

    return ((int (*)(const char *s))p->__original)(s);  // call original
}

int main(void) {

    if (__anchor_init() == ANCHOR_INIT_FAILURE)
        return -1;

    __anchor_set_hook(puts, hook);
    puts("puts() here!");

    return 0;
}
```

## Injection
To inject via `DYLD_INSERT_LIBRARIES`:
```
DYLD_FORCE_FLAT_NAMESPACE=1 DYLD_INSERT_LIBRARIES=inject.dylib ./target_program
```

If the program is already running you must use a dynamic injecting tool. Check out [`inj`]("https://github.com/kpwn/inj") by qwertyoruiop, does the job pretty well. Also be sure to turn off SIP before trying to inject into system protected processes.

Sample code for a dylib:

```
int puts_hook(const char *s) {
    ...
}

__attribute__((contructor)) void load(void) {
    __anchor_init();
    __anchor_set_hook(puts, puts_hook);
    ...
}
```
To hook local functions in the target program, just compile the _dylib_ using weak binding, and define `extern` symbols for the routines. This will compile your _dylib_ and symbols will be resolved at runtime, when injected.
