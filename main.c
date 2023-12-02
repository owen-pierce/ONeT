#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <linux/wireless.h>
#include <pthread.h>
#include "ini.h" //read
#include "ezini.h" //write

//conf static ip dhcp-host=d0:50:99:82:e7:2b,192.168.10.46

#define PROGRAM_NAME "ONeT Route"
#define AUTHOR proper_name ("Owen Pierce")

	typedef struct {
		const char* int_Name;
		const char* int_IP;
		const char* int_Mask;
		const char* int_Range_Start;
		const char* int_Range_Stop;
		const char* int_Lease_Time;
		const char* int_DNS_0;
		const char* int_DNS_1;
		const char* int_Channel;
		const char* int_Enabled;
		const char* int_Band;
		
	} int_Config;

	typedef struct {
		const char* fwd_Interface;
	} share_Config;

	typedef struct {
		const char* SSID;
		const char* PSK;
	} credentials_Config;
	typedef struct {
		const char* Country;
	} country_Code_Config;

	static int handlerInt(void* Interface, const char* section, const char* name, const char* value) {
		int_Config* pconfig = (int_Config*)Interface;
		#define match_Int(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0
		
    	if (match_Int("Interface", "int_Name")) {
    		pconfig->int_Name = strdup(value);
    	} else if (match_Int("Interface", "int_IP")) {
    		pconfig->int_IP = strdup(value);
    	} else if (match_Int("Interface", "int_Mask")) {
    		pconfig->int_Mask = strdup(value);
    	} else if (match_Int("Interface", "int_Range_Start")) {
    		pconfig->int_Range_Start = strdup(value);
    	} else if (match_Int("Interface", "int_Range_Stop")) {
    		pconfig->int_Range_Stop = strdup(value);
    	} else if (match_Int("Interface", "int_Lease_Time")) {
    		pconfig->int_Lease_Time = strdup(value);
    	} else if (match_Int("Interface", "int_DNS_0")) {
    		pconfig->int_DNS_0 = strdup(value);
    	} else if (match_Int("Interface", "int_DNS_1")) {
    		pconfig->int_DNS_1 = strdup(value);
    	} else if (match_Int("Interface", "int_Enabled")) {
    		pconfig->int_Enabled = strdup(value);
    	} else if (match_Int("Interface", "int_Band")) {
    		pconfig->int_Band = strdup(value);
    	} else if (match_Int("Interface", "int_Channel")) {
    		pconfig->int_Channel = strdup(value);
    	}
    	else {
    	    return 0;  /* unknown section/name, error */
   		}
    	return 1;
    }

	static int handlerShare(void* Share, const char* section, const char* name, const char* value) {
		share_Config* pconfig = (share_Config*)Share;
		#define match_Share(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0

		if (match_Share("Share", "fwd_Interface")) {
			pconfig->fwd_Interface = strdup(value);
		} else {
			return 0;
		}
		return 1;
	}


	static int handlerCredentials(void* Credentials, const char* section, const char* name, const char* value) {
		credentials_Config* pconfig = (credentials_Config*)Credentials;
		#define match_Credentials(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0

		if (match_Credentials("Credentials", "SSID")) {
			pconfig->SSID = strdup(value);
		} else if (match_Credentials("Credentials", "PSK")) {
			pconfig->PSK = strdup(value);
		} else {
			return 0;
		}
		return 1;
	}

	static int handlerCountryCode(void* country_Code, const char* section, const char* name, const char* value) {
		country_Code_Config* pconfig = (country_Code_Config*)country_Code;
		#define match_Country_Code(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0

		if (match_Country_Code("NetworkInfo", "Country")) {
			pconfig->Country = strdup(value);
		} else {
			return 0;
		}
		return 1;
	}

	static int parse_ext(const struct dirent *dir) {
    if(!dir)
		return 0;

    if(dir->d_type == DT_REG) { /* only deal with regular file */
        const char *ext = strrchr(dir->d_name,'.');
        if((!ext) || (ext == dir->d_name))
        	return 0;
        else {
            if(strcmp(ext, ".int") == 0)
            	return 1;
        }
    }

    return 0;
    }

	int check_wireless(const char* ifname, char* protocol) {
	  int sock = -1;
	  struct iwreq pwrq;
	  memset(&pwrq, 0, sizeof(pwrq));
	  strncpy(pwrq.ifr_name, ifname, IFNAMSIZ);

	  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
	    perror("socket");
	    return 0;
	  }

	  if (ioctl(sock, SIOCGIWNAME, &pwrq) != -1) {
	    if (protocol) strncpy(protocol, pwrq.u.name, IFNAMSIZ);
	    close(sock);
	    return 1;
	  }

	  close(sock);
	  return 0;
	}

	#define THREAD_NUM 1



int main (int argc, char *argv[]) {

    int opt;
    int d_flag = 0;
    int s_flag = 0;
    int w_flag = 0;
    int h_flag = 0;
    int g_flag = 0;
    while ((opt = getopt(argc, argv, "sdwhg")) != -1) {
        switch (opt) {
        case 'd': d_flag = 1;
        break;
        case 's': s_flag = 1;
        break;
        case 'w': w_flag = 1;
        break;
        case 'h': h_flag = 1;
        break;
        case 'g': g_flag = 1;
        break;
        default:
            fprintf(stderr, "Usage: %s [-sdwhg]\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }
    if (argc <= 1) {
        printf("Please provide atleast one argument.\n");
        return 1;
    }
    //printf("d %d s %d w %d h %d g %d\n", d_flag, s_flag, w_flag, h_flag, g_flag);

    //printf("%s\n", argv[2]);

    struct ifaddrs *ifaddr, *ifa;

	struct stat st = {0};
    ini_entry_list_t list;

	if (getuid()) {
		printf("Please run as root.\n");
		return 1;
	} else {
        char *int_Name_ini = malloc(33);
        char *int_IP_ini = malloc(16);
        char *int_Mask_ini = malloc(16);
        char *int_Range_Start_ini = malloc(16);
        char *int_Range_Stop_ini = malloc(16);
        char *int_DNS_0_ini = malloc(16);
        char *int_DNS_1_ini = malloc(16);
        char *int_Lease_Time_ini = malloc(4);
        char *int_Enabled_ini = malloc(4);
        bool int_Valid;
        char *int_Band_ini = malloc(3);
        char *int_Channel_ini = malloc(999);

        char *country_Code_ini = malloc(3);
        char *fwd_Interface_ini = malloc(33);
        char *SSID_ini = malloc(33);
        char *PASS_ini = malloc(33);

        char *save_Name = malloc(256);
        int isWireless = 0;

        strcpy(int_Name_ini, "eth0");
        strcpy(int_IP_ini, "192.168.2.1");
        strcpy(int_Mask_ini, "255.255.255.0");
        strcpy(int_Range_Start_ini, "192.168.2.2");
        strcpy(int_Range_Stop_ini, "192.168.2.254");
        strcpy(int_DNS_0_ini, "8.8.8.8");
        strcpy(int_DNS_1_ini, "8.8.4.4");
        strcpy(int_Lease_Time_ini, "12h");
        strcpy(int_Channel_ini, "0");
        strcpy(int_Enabled_ini, "0");
        strcpy(int_Band_ini, "0");
        

        strcpy(country_Code_ini, "US");
        strcpy(fwd_Interface_ini, "tun-easytether");
        strcpy(SSID_ini, "17ByteNetworkName");
        strcpy(PASS_ini, "8ByteKey");

        
        if (h_flag == 1) {
    		printf("ONeT Access:\n\nSimple network configuration tool written in C, built to create and configure 'hostapd' networks.\n");
    		printf("\nUsage: [-sdwhg]\n");
    		return 0;
    	}

        FILE *file;
        if (file = fopen("/etc/ONeT/hotspot/custom.ini", "r")) {
        	fclose(file);
        	//printf("File exists\n");

    		share_Config share_Read;
			if (ini_parse("/etc/ONeT/hotspot/custom.ini", handlerShare, &share_Read) < 0) {
       	 	printf("Can't load.\n");
     		   	return 1;
    		}
    		strncpy(fwd_Interface_ini, share_Read.fwd_Interface, 33);

    		country_Code_Config country_Read;
    		if (ini_parse("/etc/ONeT/hotspot/custom.ini", handlerCountryCode, &country_Read) < 0) {
       	 	printf("Can't load.\n");
     		   	return 1;
    		}
    		strncpy(country_Code_ini, country_Read.Country, 3);

    		credentials_Config credentials_Read;
			if (ini_parse("/etc/ONeT/hotspot/custom.ini", handlerCredentials, &credentials_Read) < 0) {
    	    	printf("Can't load.\n");
    	    	return 1;
    		}
    		strncpy(SSID_ini, credentials_Read.SSID, 33);
    		strncpy(PASS_ini, credentials_Read.PSK, 33);

    		free((void*)credentials_Read.SSID);
    		free((void*)credentials_Read.PSK);
    		free((void*)country_Read.Country);
    		free((void*)share_Read.fwd_Interface);

        } else {
       		printf("File does not exist\n");
       		printf("Checking for path:\n");

        	if (stat("/etc/ONeT/", &st) == -1) {
        		mkdir("/etc/ONeT", 0700);
       			if (stat("/etc/ONeT/", &st) == -1) {
       				printf("Critical error making folder 'ONeT'\n");
       				return 1;
       			}
       			printf("Folder: 'ONeT' created.\n");
        	}
        	if (stat("/etc/ONeT/hotspot", &st) == -1) {
       			mkdir("/etc/ONeT/hotspot/", 0700);
       			if (stat("/etc/ONeT/hotspot/", &st) == -1) {
       				printf("Critical error making folder 'hotspot'\n");
       				return 1;
       			}
       			printf("Folder: 'hotspot' created.\n");
        	}
        	if (stat("/etc/ONeT/hotspot/config/", &st) == -1) {
       			mkdir("/etc/ONeT/hotspot/config/", 0700);
       			if (stat("/etc/ONeT/hotspot/config/", &st) == -1) {
       				printf("Critical error making folder 'config'\n");
       				return 1;
       			}
        		printf("Folder: 'config' created.\n");
        	}

       		list = NULL;
    		AddEntryToList(&list, "Credentials", "SSID", SSID_ini);
   			AddEntryToList(&list, "Credentials", "PSK", PASS_ini);
    		AddEntryToList(&list, "Share", "fwd_Interface", fwd_Interface_ini);
   			AddEntryToList(&list, "NetworkInfo", "Country", country_Code_ini);

   			if (0 != MakeINIFile("/etc/ONeT/hotspot/custom.ini", list)) {
        		printf("Error making ini\n");
    		}
    		FreeList(list);

    		share_Config share_Read;
			if (ini_parse("/etc/ONeT/hotspot/custom.ini", handlerShare, &share_Read) < 0) {
       			printf("Can't load.\n");
     	   		return 1;
   			}
    		strncpy(fwd_Interface_ini, share_Read.fwd_Interface, 33);

    		country_Code_Config country_Read;
    		if (ini_parse("/etc/ONeT/hotspot/custom.ini", handlerCountryCode, &country_Read) < 0) {
       	 		printf("Can't load.\n");
     	   		return 1;
    		}
    		strncpy(country_Code_ini, country_Read.Country, 3);
    		
    		credentials_Config credentials_Read;
			if (ini_parse("/etc/ONeT/hotspot/custom.ini", handlerCredentials, &credentials_Read) < 0) {
    	   		printf("Can't load.\n");
    	   		return 1;
    		}
    		strncpy(SSID_ini, credentials_Read.SSID, 33);
    		strncpy(PASS_ini, credentials_Read.PSK, 33);
        }

    	if (g_flag == 1) {
    	list = NULL;
   		AddEntryToList(&list, "Interface", "int_Name", int_Name_ini);
   		AddEntryToList(&list, "Interface", "int_IP", int_IP_ini);
   		AddEntryToList(&list, "Interface", "int_Mask", int_Mask_ini);
   		AddEntryToList(&list, "Interface", "int_Range_Start", int_Range_Start_ini);
    	AddEntryToList(&list, "Interface", "int_Range_Stop", int_Range_Stop_ini);
    	AddEntryToList(&list, "Interface", "int_DNS_0", int_DNS_0_ini);
    	AddEntryToList(&list, "Interface", "int_DNS_1", int_DNS_1_ini);
   		AddEntryToList(&list, "Interface", "int_Lease_Time", int_Lease_Time_ini);
   		AddEntryToList(&list, "Interface", "int_Enabled", int_Enabled_ini);
   		AddEntryToList(&list, "Interface", "int_Channel", int_Channel_ini);
    	AddEntryToList(&list, "Interface", "int_Band", int_Band_ini);
    	

    	if (0 != MakeINIFile("/etc/ONeT/hotspot/config/default.int", list)) {
    	   	printf("Error creating default.int\n");
    	} else {
    		printf("File: '/etc/ONeT/hotspot/config/default.int' created.\n");
   		}
   		FreeList(list);	
    	return 0;
    	}

        if (d_flag != 1) {

        	int pid_Killall = fork();
        	if (pid_Killall == -1) {
        		return 1;
        	} else if (pid_Killall == 0) {
        	execlp("killall", "killall", "wpa_supplicant", NULL);
    		} else {
    			wait(NULL);
    			//printf("Complete: killall wpa_supplicant\n");
    		}

        	int pid_Rfkill = fork();
        	if (pid_Rfkill == -1) {
        		return 1;
        	} else if (pid_Rfkill == 0) {
        	execlp("sh", "sh", "-c", "rfkill unblock wlan", NULL);
    		} else {
    			wait(NULL);
    			//printf("Complete: rfkill\n");
    		}

        	int pid_Systemctl_Net = fork();
        	if (pid_Systemctl_Net == -1) {
        		return 1;
        	} else if (pid_Systemctl_Net == 0) {
        	execlp("sh", "sh","-c" , "systemctl restart systemd-networkd systemd-resolved", NULL);
    		} else {
    			wait(NULL);
    			//printf("Complete: systemctl restart systemd-networkd systemd-resolved\n");
    		}
        	int pid_Systemctl_Reload = fork();
        	if (pid_Systemctl_Reload == -1) {
        		return 1;
        	} else if (pid_Systemctl_Reload == 0) {
        	execlp("systemctl", "systemctl", "daemon-reload", NULL);
    		} else {
    			wait(NULL);
    			//printf("Complete: systemctl daemon-reload\n");
    		}
    		if (remove("/etc/dnsmasq.d/custom-dnsmasq.conf") == 0) {
   			}

    	}

		struct dirent **namelist;
        int n;

        n = scandir("/etc/ONeT/hotspot/config/", &namelist, parse_ext, alphasort);
        if (n < 0) {
        	perror("scandir");
            return 1;
        }
        else {
        	if (n < 1) {
        		printf("No .int\n");
        	} else {
            	while (n--) {
            		char *src = malloc(256); //27 bytes used 256 alloc
                	strcpy(src, "/etc/ONeT/hotspot/config/");
                	char *dst = malloc(256);
                	strcpy(dst, namelist[n]->d_name);
                	strcat(src,dst);
                	printf("\nLoading: %s\n\n", dst);
                	int_Config int_Read;
    				if (ini_parse(src, handlerInt, &int_Read) < 0) {
        				printf("Can't load.\n");
        				return 1;
    				}
    				free(dst);
    				free(src);


    				//ADD CHECK FOR NUM/APLHA NUM INPUT
    			    strncpy(int_Name_ini, int_Read.int_Name, 33);
    			    //printf("Interface Name: %s\n", int_Name_ini);
    			    strncpy(int_IP_ini, int_Read.int_IP, 17);
    			    //printf("Interface IP: %s\n", int_IP_ini);
    			    strncpy(int_Mask_ini, int_Read.int_Mask, 17);
    			    //printf("Interface Mask: %s\n", int_Mask_ini);
    			    strncpy(int_Range_Start_ini, int_Read.int_Range_Start, 17);
    			    //printf("Interface Range Start: %s\n", int_Range_Start_ini);
    			    strncpy(int_Range_Stop_ini, int_Read.int_Range_Stop, 17);
    			    //printf("Interface Range Stop: %s\n", int_Range_Stop_ini);
    			    strncpy(int_DNS_0_ini, int_Read.int_DNS_0, 17);
    			    //printf("Interface DNS 0: %s\n", int_DNS_0_ini);
    			    strncpy(int_DNS_1_ini, int_Read.int_DNS_1, 17);
    			    //printf("Interface DNS 1: %s\n", int_DNS_1_ini);
    			    strncpy(int_Lease_Time_ini, int_Read.int_Lease_Time, 4);
    			    //printf("Interface Lease Time: %s\n", int_Lease_Time_ini);
    			    strncpy(int_Enabled_ini, int_Read.int_Enabled, 3);
    			    //printf("Interface Enabled: %s\n", int_Enabled_ini);
    			    strncpy(int_Band_ini, int_Read.int_Band, 2);
    			    //printf("Interface Band: %s\n", int_Band_ini);
    			    strncpy(int_Channel_ini, int_Read.int_Channel, 999);
    			    //printf("Interface Channel: %s\n", int_Channel_ini);   			    

					int isNIC = 0;
				    if (getifaddrs(&ifaddr) == -1) {
				    	perror("getifaddrs");
				    	return -1;
				  	}

					for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
				    	char protocol[IFNAMSIZ]  = {0};

						if (ifa->ifa_addr == NULL ||
							ifa->ifa_addr->sa_family != AF_PACKET) continue;

						if (strcmp(ifa->ifa_name, int_Name_ini) == 0) {
				    		isNIC = 1;
				    	//printf("Found card\n");
				    } 

    				if (check_wireless(ifa->ifa_name, protocol)) {
      					if (strcmp(ifa->ifa_name, int_Name_ini)==0) {
      						isWireless = 1;
      						//printf("interface %s is wireless: %s\n", ifa->ifa_name, protocol);
      					}
    				}
					}
					freeifaddrs(ifaddr);

					if (isNIC == 0) {
				  		printf("Network interface not connected, skipping:\n");
			    	} else {

    				if (strcmp(int_Enabled_ini, "1") == 0) {

    					printf("\nInterface: '%s' Enabled.\n\n", int_Name_ini);

    			    	printf("Interface Name: %s\n", int_Name_ini);
    			    	printf("Interface IP: %s\n", int_IP_ini);
    			    	printf("Interface Mask: %s\n", int_Mask_ini);
    			    	printf("Interface Range Start: %s\n", int_Range_Start_ini);
    			    	printf("Interface Range Stop: %s\n", int_Range_Stop_ini);
    			    	printf("Interface DNS 0: %s\n", int_DNS_0_ini);
    			    	printf("Interface DNS 1: %s\n", int_DNS_1_ini);
    			    	printf("Interface Lease Time: %s\n", int_Lease_Time_ini);
    			    	printf("Interface Enabled: %s\n", int_Enabled_ini);
    			    	printf("Interface Band: %s\n", int_Band_ini);
    			    	printf("Interface Channel: %s\n", int_Channel_ini);


    					FILE *fwdW;
    					fwdW = fopen("/proc/sys/net/ipv4/ip_forward", "w");
    					if(fwdW == NULL) {
    						printf("error\n");
    						return 1;
    					} else {
    						fprintf(fwdW, "1");
    						fclose(fwdW);
    					}

						FILE *fptr;
						fptr = fopen("/etc/dnsmasq.d/custom-dnsmasq.conf","a");
						if(fptr == NULL) {
							printf("error\n");
							return 1;
						} else {
							fprintf(fptr, "interface=%s\n", int_Name_ini);
							fprintf(fptr, "bind-interfaces\n");
							fprintf(fptr, "server=%s\n", int_DNS_0_ini);
							fprintf(fptr, "server=%s\n", int_DNS_1_ini);
							fprintf(fptr, "domain-needed\n");
							fprintf(fptr, "bogus-priv\n");
							fprintf(fptr, "dhcp-range=%s,%s,%s\n", int_Range_Start_ini,int_Range_Stop_ini,int_Lease_Time_ini);
							fclose(fptr);
						}

    					if (d_flag != 1 && s_flag == 1) {
    					
							if (isWireless == 0) {

								char *src = malloc(256);
								char *dst = malloc(256);
								strcpy(src, "ifconfig ");
								strcpy(dst, int_Name_ini);
								strcat(src,dst);
								strcpy(dst, " down");
								strcat(src,dst);

								int pid_ifConfig_0 = fork();
        						if (pid_ifConfig_0 == -1) {
        							return 1;
        						} else if (pid_ifConfig_0 == 0) {
        							execlp("sh", "sh", "-c", src, NULL);
    							} else {
    								wait(NULL);
    								//printf("Complete: ifconfig\n");
    							}

								strcpy(src, "iptables -A FORWARD -i ");
								strcpy(dst, fwd_Interface_ini);
								strcat(src,dst);
								strcpy(dst, " -o ");
								strcat(src,dst);
								strcpy(dst, int_Name_ini);
								strcat(src, dst);
								strcpy(dst, " -m state --state RELATED,ESTABLISHED -j ACCEPT");
								strcat(src, dst);

    							int pid_ipTables_0 = fork();
    							if (pid_ipTables_0 == -1) {
    								return 1;
    							} else if (pid_ipTables_0 == 0) {
    								execlp("sh", "sh", "-c", src,NULL);
    							} else {
    								wait(NULL);
    								//printf("Done\n");
    							}

								strcpy(src, "iptables -A FORWARD -i ");
								strcpy(dst, int_Name_ini);
								strcat(src,dst);
								strcpy(dst, " -o ");
								strcat(src,dst);
								strcpy(dst, fwd_Interface_ini);
								strcat(src, dst);
								strcpy(dst, " -j ACCEPT");
								strcat(src, dst);

    							int pid_ipTables_1 = fork();
    							if (pid_ipTables_1 == -1) {
    								return 1;
    							} else if (pid_ipTables_1 == 0) {
    								execlp("sh", "sh", "-c", src, NULL);
    							} else {
    								wait(NULL);
    								//printf("Done\n");
    							}

								strcpy(src, "ifconfig ");
								strcpy(dst, int_Name_ini);
								strcat(src,dst);
								strcpy(dst, " ");
								strcat(src,dst);
								strcpy(dst, int_IP_ini);
								strcat(src, dst);
								strcpy(dst, " netmask ");
								strcat(src, dst);
								strcpy(dst, int_Mask_ini);
								strcat(src, dst);

    							int pid_ifConfig_1 = fork();
    							if (pid_ifConfig_1 == -1) {
    								return 1;
    							} else if (pid_ifConfig_1 == 0) {
    								execlp("sh", "sh", "-c", src, NULL);
    							} else {
    								wait(NULL);
    								//printf("Done ifconfig 1\n");
    							}
    							
								strcpy(src, "ip route del 0/0 dev ");
								strcpy(dst, int_Name_ini);
								strcat(src,dst);

    							int pid_ipRoute_0 = fork();
    							if (pid_ipRoute_0 == -1) {
    								return 1;
    							} else if (pid_ipRoute_0 == 0) {
    								execlp("sh", "sh", "-c", src, NULL);
    							} else {
    								wait(NULL);
    								//printf("Done ip route\n");
    							}

    							int pid_Systemctl_0 = fork();
    							if (pid_Systemctl_0 == -1) {
    								return 1;
    							} else if (pid_Systemctl_0 == 0) {
    								execlp("sh", "sh", "-c", "systemctl restart dnsmasq", NULL);
    							} else {
    								wait(NULL);
    								//printf("Done\n");
    							}

								strcpy(src, "ifconfig ");
								strcpy(dst, int_Name_ini);
								strcat(src,dst);
								strcpy(dst, " up");
								strcat(src,dst);

    							int pid_ifConfig_2 = fork();
    							if (pid_ifConfig_2 == -1) {
    								return 1;
    							} else if (pid_ifConfig_2 == 0) {
    								execlp("sh", "sh", "-c", src, NULL);
    							} else {
    								wait(NULL);
    								//printf("Done\n");
    							}
    							free(src);
    							free(dst);

    						} else if (isWireless == 1) {

    							if (strcmp(int_Band_ini, "0") == 0) {

    								char *int_Name_Char = malloc(256);
    								strcpy(save_Name, "/etc/ONeT/hotspot/hostapd-24g-");
    								strcpy(int_Name_Char, int_Name_ini);
    								strcat(save_Name, int_Name_Char);
    								free(int_Name_Char);
    								
    								FILE *writeAPD;
    								remove(save_Name) == 0;
    								writeAPD = fopen(save_Name, "a");
    								if(writeAPD == NULL) {
    									return 1;
    								} else {
										fprintf(writeAPD, "interface=%s\n", int_Name_ini);
										fprintf(writeAPD, "driver=nl80211\n");
										fprintf(writeAPD, "ht_capab=[HT40][SHORT-GI-20][DSSS_CCK-40]\n");
										fprintf(writeAPD, "ignore_broadcast_ssid=0\n");
										fprintf(writeAPD, "hw_mode=g\n");
										fprintf(writeAPD, "channel=%s\n", int_Channel_ini);
										fprintf(writeAPD, "country_code=%s\n",country_Code_ini);
										fprintf(writeAPD, "ieee80211n=1\n");
										fprintf(writeAPD, "wmm_enabled=1\n");
										fprintf(writeAPD, "ssid=%s\n", SSID_ini);
										fprintf(writeAPD, "auth_algs=1\n");
										fprintf(writeAPD, "wpa=2\n");
										fprintf(writeAPD, "wpa_key_mgmt=WPA-PSK\n");
										fprintf(writeAPD, "rsn_pairwise=CCMP\n");
										fprintf(writeAPD, "wpa_passphrase=%s\n", PASS_ini);
										fclose(writeAPD);
    								}
    							} else if (strcmp(int_Band_ini, "1") == 0) {

    								char *int_Name_Char = malloc(256);
    								strcpy(save_Name, "/etc/ONeT/hotspot/hostapd-5g-");
    								strcpy(int_Name_Char, int_Name_ini);
    								strcat(save_Name, int_Name_Char);
    								free(int_Name_Char);
    								    								FILE *writeAPD;
    								remove(save_Name) == 0;
    								writeAPD = fopen(save_Name, "a");
    								if(writeAPD == NULL) {
    									return 1;
    								} else {
										fprintf(writeAPD, "interface=%s\n", int_Name_ini);
										fprintf(writeAPD, "driver=nl80211\n");
										fprintf(writeAPD, "macaddr_acl=0\n");
										fprintf(writeAPD, "ht_capab=[HT40][SHORT-GI-20][DSSS_CCK-40]\n");
										fprintf(writeAPD, "ignore_broadcast_ssid=0\n");
										fprintf(writeAPD, "hw_mode=a\n");
										fprintf(writeAPD, "channel=%s\n", int_Channel_ini);
										fprintf(writeAPD, "ieee80211d=1\n");
										fprintf(writeAPD, "country_code=%s\n",country_Code_ini);
										fprintf(writeAPD, "ieee80211n=1\n");
										fprintf(writeAPD, "ieee80211ac=1\n");
										fprintf(writeAPD, "wmm_enabled=1\n");
										fprintf(writeAPD, "ssid=%s\n", SSID_ini);
										fprintf(writeAPD, "auth_algs=1\n");
										fprintf(writeAPD, "wpa=2\n");
										fprintf(writeAPD, "wpa_key_mgmt=WPA-PSK\n");
										fprintf(writeAPD, "rsn_pairwise=CCMP\n");
										fprintf(writeAPD, "wpa_passphrase=%s\n", PASS_ini);
										fclose(writeAPD);
    								}
    							}

								char *src = malloc(256);
								char *dst = malloc(256);
								strcpy(src, "ifconfig ");
								strcpy(dst, int_Name_ini);
								strcat(src,dst);
								strcpy(dst, " down");
								strcat(src,dst);

								int pid_ifConfig_0 = fork();

        						if (pid_ifConfig_0 == -1) {
        							return 1;
        						} else if (pid_ifConfig_0 == 0) {
        							execlp("sh", "sh", "-c", src, NULL);
    							} else {
    								wait(NULL);
    								//printf("Complete: ifconfig\n");
    							}

								strcpy(src, "iptables -A FORWARD -i ");
								strcpy(dst, fwd_Interface_ini);
								strcat(src,dst);
								strcpy(dst, " -o ");
								strcat(src,dst);
								strcpy(dst, int_Name_ini);
								strcat(src, dst);
								strcpy(dst, " -m state --state RELATED,ESTABLISHED -j ACCEPT");
								strcat(src, dst);

    							int pid_ipTables_0 = fork();
    							if (pid_ipTables_0 == -1) {
    								return 1;
    							} else if (pid_ipTables_0 == 0) {
    								execlp("sh", "sh", "-c", src,NULL);
    							} else {
    								wait(NULL);
    								//printf("Done\n");
    							}

								strcpy(src, "iptables -A FORWARD -i ");
								strcpy(dst, int_Name_ini);
								strcat(src,dst);
								strcpy(dst, " -o ");
								strcat(src,dst);
								strcpy(dst, fwd_Interface_ini);
								strcat(src, dst);
								strcpy(dst, " -j ACCEPT");
								strcat(src, dst);

    							int pid_ipTables_1 = fork();
    							if (pid_ipTables_1 == -1) {
    								return 1;
    							} else if (pid_ipTables_1 == 0) {
    								execlp("sh", "sh", "-c", src, NULL);
    							} else {
    								wait(NULL);
    								//printf("Done\n");
    							}

								strcpy(src, "ifconfig ");
								strcpy(dst, int_Name_ini);
								strcat(src,dst);
								strcpy(dst, " ");
								strcat(src,dst);
								strcpy(dst, int_IP_ini);
								strcat(src, dst);
								strcpy(dst, " netmask ");
								strcat(src, dst);
								strcpy(dst, int_Mask_ini);
								strcat(src, dst);

    							int pid_ifConfig_1 = fork();
    							if (pid_ifConfig_1 == -1) {
    								return 1;
    							} else if (pid_ifConfig_1 == 0) {
    								execlp("sh", "sh", "-c", src, NULL);
    							} else {
    								wait(NULL);
    								//printf("Done ifconfig 1\n");
    							}
    							
								strcpy(src, "ip route del 0/0 dev ");
								strcpy(dst, int_Name_ini);
								strcat(src,dst);

    							int pid_ipRoute_0 = fork();
    							if (pid_ipRoute_0 == -1) {
    								return 1;
    							} else if (pid_ipRoute_0 == 0) {
    								execlp("sh", "sh", "-c", src, NULL);
    							} else {
    								wait(NULL);
    								//printf("Done ip route\n");
    							}

    							int pid_Systemctl_0 = fork();
    							if (pid_Systemctl_0 == -1) {
    								return 1;
    							} else if (pid_Systemctl_0 == 0) {
    								execlp("sh", "sh", "-c", "systemctl restart dnsmasq", NULL);
    							} else {
    								wait(NULL);
    								//printf("Done\n");
    							}
    							free(src);
    							free(dst);
    								
    							char *srce = malloc(256);
    							char *dste = malloc(256);
    							strcpy(dste, "hostapd ");
    							strcat(dste, save_Name);
    							//strcpy(srce, " &");
    							//strcat(dste, srce);
    							//strcpy(srce, " > /dev/null");
    							//strcat(dste, srce);

								void* routine(void* args){
									//sleep(1);
									//int a = system(dste);
									int pid_Hostapd = fork();
									if (pid_Hostapd == -1) {
										execlp(dste, NULL);
									} else {
										wait(NULL);
									}
    								if (remove("/home/root/router/thread") == 0) {
   									}
									printf("Hotspot started.\n");

								}

								pthread_t th[THREAD_NUM];
								pthread_attr_t detachedThread;
								pthread_attr_init(&detachedThread);
								pthread_attr_setdetachstate(&detachedThread, PTHREAD_CREATE_DETACHED);
								int i;
								for (i = 0; i < THREAD_NUM; i++) {
									if (pthread_create(&th[i], &detachedThread, &routine, NULL) != 0) {
										perror("Fatal");
									}
								pthread_detach(th[i]);
								}

								// for (i = 0; i < THREAD_NUM; i++) {
								// 	if (pthread_join(th[i], NULL) != 0 ) {
								// 		perror("Fatal");
								// 	}
								// }

								//pthread_attr_destroy(&detachedThread);
								pthread_exit(0);
								// return 0;
    							


    						} else {
    							printf("Interface type invalid.\n");
    					} 
    					}
    				} else {
    					printf("Interface: %s disabled.\n", int_Name_ini);
    				}
    				free(namelist[n]);
            	}
        	}
            free(namelist);

        }
    }

		return 0;
	}
}