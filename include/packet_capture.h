#include "util.h"

/*
 * start_capture(interface)
 *   Opens the interface using libpcap and starts capture loop in current thread.
 *   Returns 0 on success, -1 on failure.
 */
int start_capture(const char *interface);

/*
 * stop_capture()
 *   Stop the capture loop and close resources.
 */
void stop_capture(void);
