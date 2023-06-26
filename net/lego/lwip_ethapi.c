#include <lego/fit_ibapi.h>
#include <net/lwip/sockets.h>


int ibapi_receive_message(unsigned int designed_port, void *ret_addr, int receive_size, uintptr_t *descriptor)
{
    
}

int ibapi_send(int target_node, void *addr, int size)
{

}

int ibapi_send_reply_imm(int target_node, void *addr, int size, void *ret_addr,
			 int max_ret_size, int if_use_ret_phys_addr)
{

}

int ibapi_send_reply_timeout(int target_node, void *addr, int size, void *ret_addr,
			     int max_ret_size, int if_use_ret_phys_addr,
			     unsigned long timeout_sec);


/** Following are functions which are not used */
void ibapi_free_recv_buf(void *input_buf);
inline int ibapi_reply_message_w_extra_bits(void *addr, int size, int bits, uintptr_t descriptor);
inline int ibapi_reply_message_nowait(void *addr, int size, uintptr_t descriptor);
inline int ibapi_reply_message_w_extra_bits_nowait(void *addr, int size, int bits, uintptr_t descriptor);
int ibapi_receive_message_no_reply(unsigned int designed_port,
		void *ret_addr, int receive_size);
int ibapi_send_reply_timeout_w_private_bits(int target_node, void *addr, int size,  void *ret_addr,
			     int max_ret_size, int *private_bits, int if_use_ret_phys_addr,
			     unsigned long timeout_sec);

int ibapi_multicast_send_reply_timeout(int num_nodes, int *target_node, 
				struct fit_sglist *sglist, struct fit_sglist *output_msg,
				int max_ret_size, int if_use_ret_phys_addr, unsigned long timeout_sec);
int ibapi_get_node_id(void);
int ibapi_num_connected_nodes(void);