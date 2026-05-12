#include <ncurses.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define VERSION "1.0"
#define LOG_FILE "/var/log/coltan-console.log"
#define IFACES_FILE "/usr/local/etc/coltan/interfaces.json"
#define USERS_FILE "/usr/local/etc/coltan/users.json"
#define NODE "/usr/local/bin/node"

#define CLR_GREEN  1
#define CLR_CYAN   2
#define CLR_YELLOW 3
#define CLR_RED    4
#define CLR_GRAY   5
#define CLR_WHITE  6
#define CLR_BLUE   7

/* Ejecutar comando y guardar resultado en buf (no estatico) */
void cmd_output(const char *cmd, char *buf, int buflen) {
    buf[0] = '\0';
    FILE *fp = popen(cmd, "r");
    if (!fp) return;
    if (fgets(buf, buflen, fp)) buf[strcspn(buf, "\n")] = 0;
    pclose(fp);
}

/* Verificar password contra /etc/master.passwd (para root) */
int verify_system_user(const char *user, const char *pass) {
    FILE *f = fopen("/etc/master.passwd", "r");
    if (!f) return 0;
    char line[512], stored[256] = {0};
    char prefix[64];
    snprintf(prefix, sizeof(prefix), "%s:", user);
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, prefix, strlen(prefix)) == 0) {
            char *start = line + strlen(prefix);
            char *end = strchr(start, ':');
            if (end) { *end = 0; strncpy(stored, start, sizeof(stored)-1); }
            break;
        }
    }
    fclose(f);
    if (!strlen(stored) || stored[0] == '*') return 0;
    char *result = crypt(pass, stored);
    return result && strcmp(result, stored) == 0;
}

/* Verificar password contra users.json con node (para admin del panel) */
int verify_panel_user(const char *user, const char *pass) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        NODE " -e \""
        "const fs=require('fs'),bcrypt=require('/opt/coltanos/backend/node_modules/bcrypt');"
        "try{"
        "  const u=JSON.parse(fs.readFileSync('%s','utf8')).find(function(x){return x.username==='%s';});"
        "  if(!u)process.exit(1);"
        "  bcrypt.compare('%s',u.password,function(e,r){process.exit(r?0:1);});"
        "}catch(e){process.exit(1);}\" 2>/dev/null",
        USERS_FILE, user, pass);
    int ret = system(cmd);
    return ret == 0;
}

int verify_password(const char *user, const char *pass) {
    /* Primero intentar panel web (admin), luego sistema (root) */
    if (verify_panel_user(user, pass)) return 1;
    if (verify_system_user(user, pass)) return 1;
    return 0;
}

void log_msg(const char *msg) {
    FILE *f = fopen(LOG_FILE, "a");
    if (!f) return;
    time_t t = time(NULL);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&t));
    fprintf(f, "[%s] %s\n", buf, msg);
    fclose(f);
}

void run_cmd_win(const char *cmd, WINDOW *win) {
    FILE *fp = popen(cmd, "r");
    if (!fp) return;
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = 0;
        wattron(win, COLOR_PAIR(CLR_GRAY));
        wprintw(win, "  %s\n", line);
        wattroff(win, COLOR_PAIR(CLR_GRAY));
        wrefresh(win);
    }
    pclose(fp);
}

/* Input normal — retorna 1 si el usuario escribio B (volver) */
int get_input(WINDOW *win, int y, int x, char *buf, int maxlen) {
    buf[0] = '\0';
    echo();
    curs_set(1);
    wmove(win, y, x);
    wgetnstr(win, buf, maxlen - 1);
    noecho();
    curs_set(0);
    if (strcmp(buf, "b") == 0 || strcmp(buf, "B") == 0) return 1;
    return 0;
}

/* Input secreto — sin echo, sin asteriscos */
void get_secret(WINDOW *win, int y, int x, char *buf, int maxlen) {
    buf[0] = '\0';
    noecho();
    curs_set(1);
    wmove(win, y, x);
    wrefresh(win);
    int i = 0, ch;
    while (1) {
        ch = wgetch(win);
        if (ch == '\n' || ch == '\r' || ch == KEY_ENTER) break;
        if (ch == KEY_BACKSPACE || ch == 127 || ch == 8) { if (i > 0) i--; }
        else if (ch >= 32 && ch <= 126 && i < maxlen-1) buf[i++] = (char)ch;
    }
    buf[i] = '\0';
    curs_set(0);
    noecho();
}

/* Banner simple y legible */
void draw_banner(WINDOW *win) {
    wclear(win);
    wattron(win, COLOR_PAIR(CLR_GREEN) | A_BOLD);
    mvwprintw(win, 1, 2, "  ####   ####   #      #####   ####   #   #      ####    #### ");
    mvwprintw(win, 2, 2, " #      #    #  #        #    #    #  ##  #     #    #  #     ");
    mvwprintw(win, 3, 2, " #      #    #  #        #    ######  # # #     #    #   #### ");
    mvwprintw(win, 4, 2, " #      #    #  #        #    #    #  #  ##     #    #      # ");
    mvwprintw(win, 5, 2, "  ####   ####   ######   #    #    #  #   #      ####   ####  ");
    wattroff(win, COLOR_PAIR(CLR_GREEN) | A_BOLD);
    wattron(win, COLOR_PAIR(CLR_CYAN));
    mvwprintw(win, 6, 2, "         Network Security OS v%s  -  by Enrique Molina", VERSION);
    wattroff(win, COLOR_PAIR(CLR_CYAN));
    wattron(win, COLOR_PAIR(CLR_GRAY));
    mvwprintw(win, 7, 2, " ----------------------------------------------------------------");
    wattroff(win, COLOR_PAIR(CLR_GRAY));
    wrefresh(win);
}

void draw_sysinfo(WINDOW *win, int sy) {
    /* Usar buffers separados para cada valor */
    char hostname[64], freebsd[64], uptime[64];
    char wan_if[32], lan_if[32], wan_ip[64], lan_ip[64];
    char wan_cmd[128], lan_cmd[128];

    cmd_output("hostname", hostname, sizeof(hostname));
    cmd_output("freebsd-version | cut -d- -f1,2", freebsd, sizeof(freebsd));
    cmd_output("uptime | sed 's/.*up //' | sed 's/,.*//'", uptime, sizeof(uptime));
    cmd_output("/usr/local/bin/coltan-iface WAN 2>/dev/null", wan_if, sizeof(wan_if));
    cmd_output("/usr/local/bin/coltan-iface LAN 2>/dev/null", lan_if, sizeof(lan_if));
    if (!strlen(wan_if)) strcpy(wan_if, "re0");
    if (!strlen(lan_if)) strcpy(lan_if, "re1");

    snprintf(wan_cmd, sizeof(wan_cmd), "ifconfig %s 2>/dev/null | grep 'inet ' | awk '{print $2}'", wan_if);
    snprintf(lan_cmd, sizeof(lan_cmd), "ifconfig %s 2>/dev/null | grep 'inet ' | awk '{print $2}'", lan_if);
    cmd_output(wan_cmd, wan_ip, sizeof(wan_ip));
    cmd_output(lan_cmd, lan_ip, sizeof(lan_ip));

    int pf_on  = system("pfctl -s info 2>/dev/null | grep -q Enabled") == 0;
    int dns_on = system("service unbound status 2>/dev/null | grep -q running") == 0;
    int kea_on = system("service kea status 2>/dev/null | grep -q 'DHCPv4 server: active'") == 0;
    int pm2_on = system("pm2 list 2>/dev/null | grep -q online") == 0;

    /* Fila 1: HOST y FreeBSD */
    wattron(win, COLOR_PAIR(CLR_GRAY));
    mvwprintw(win, sy, 2, " HOST:    ");
    wattroff(win, COLOR_PAIR(CLR_GRAY));
    wattron(win, COLOR_PAIR(CLR_CYAN));
    wprintw(win, "%-20s", hostname);
    wattroff(win, COLOR_PAIR(CLR_CYAN));
    wattron(win, COLOR_PAIR(CLR_GRAY));
    mvwprintw(win, sy, 42, "FreeBSD: ");
    wattroff(win, COLOR_PAIR(CLR_GRAY));
    wattron(win, COLOR_PAIR(CLR_CYAN));
    wprintw(win, "%s", freebsd);
    wattroff(win, COLOR_PAIR(CLR_CYAN));

    /* Fila 2: WAN */
    wattron(win, COLOR_PAIR(CLR_GRAY));
    mvwprintw(win, sy+1, 2, " WAN:     ");
    wattroff(win, COLOR_PAIR(CLR_GRAY));
    wattron(win, COLOR_PAIR(CLR_CYAN));
    wprintw(win, "%-8s  %s", wan_if, strlen(wan_ip) ? wan_ip : "no IP");
    wattroff(win, COLOR_PAIR(CLR_CYAN));

    /* Fila 3: LAN */
    wattron(win, COLOR_PAIR(CLR_GRAY));
    mvwprintw(win, sy+2, 2, " LAN:     ");
    wattroff(win, COLOR_PAIR(CLR_GRAY));
    wattron(win, COLOR_PAIR(CLR_CYAN));
    wprintw(win, "%-8s  %s", lan_if, strlen(lan_ip) ? lan_ip : "no IP");
    wattroff(win, COLOR_PAIR(CLR_CYAN));

    /* Fila 4: UPTIME */
    wattron(win, COLOR_PAIR(CLR_GRAY));
    mvwprintw(win, sy+3, 2, " UPTIME:  ");
    wattroff(win, COLOR_PAIR(CLR_GRAY));
    wattron(win, COLOR_PAIR(CLR_CYAN));
    wprintw(win, "%s", uptime);
    wattroff(win, COLOR_PAIR(CLR_CYAN));

    /* Separador servicios */
    wattron(win, COLOR_PAIR(CLR_GRAY));
    mvwprintw(win, sy+4, 2, " ----------------------------------------------------------------");
    mvwprintw(win, sy+5, 2, " SERVICES:  ");
    wattroff(win, COLOR_PAIR(CLR_GRAY));

    struct { int on; const char *name; } svcs[] = {
        {pf_on,"PF"},{dns_on,"DNS"},{kea_on,"DHCP"},{pm2_on,"WebUI"}
    };
    int sx = 14;
    for (int i = 0; i < 4; i++) {
        wattron(win, COLOR_PAIR(svcs[i].on ? CLR_GREEN : CLR_RED));
        mvwprintw(win, sy+5, sx, "[%s]", svcs[i].name);
        wattroff(win, COLOR_PAIR(svcs[i].on ? CLR_GREEN : CLR_RED));
        sx += (int)strlen(svcs[i].name) + 4;
    }

    wattron(win, COLOR_PAIR(CLR_GRAY));
    mvwprintw(win, sy+6, 2, " ----------------------------------------------------------------");
    wattroff(win, COLOR_PAIR(CLR_GRAY));

    char url[64];
    snprintf(url, sizeof(url), "http://%s:3000", strlen(lan_ip) ? lan_ip : "192.168.11.1");
    wattron(win, COLOR_PAIR(CLR_GRAY));  mvwprintw(win, sy+7, 2, " Web UI:  ");
    wattroff(win, COLOR_PAIR(CLR_GRAY));
    wattron(win, COLOR_PAIR(CLR_CYAN));  wprintw(win, "%s", url);
    wattroff(win, COLOR_PAIR(CLR_CYAN));
    wrefresh(win);
}

void draw_menu(WINDOW *win, int sy) {
    wattron(win, COLOR_PAIR(CLR_WHITE) | A_BOLD);
    mvwprintw(win, sy, 2, " CONSOLE MENU");
    wattroff(win, COLOR_PAIR(CLR_WHITE) | A_BOLD);

    struct { const char *num; const char *label; int color; } items[] = {
        {"1","Assign interfaces",     CLR_WHITE},
        {"2","Set IP addresses",      CLR_WHITE},
        {"3","Reset web UI password", CLR_WHITE},
        {"4","Ping host",             CLR_WHITE},
        {"5","Restart services",      CLR_WHITE},
        {"6","Reload firewall",       CLR_WHITE},
        {"7","Update Coltan OS",      CLR_WHITE},
        {"8","Reboot",                CLR_YELLOW},
        {"9","Shutdown",              CLR_RED},
        {"0","Shell (admin only)",    CLR_BLUE},
        {"C","Cerrar sesion",         CLR_YELLOW},
        {"I","Info / Creditos",       CLR_GRAY},
    };
    for (int i = 0; i < 12; i++) {
        wattron(win, COLOR_PAIR(CLR_BLUE));
        mvwprintw(win, sy+1+i, 2, " %s)", items[i].num);
        wattroff(win, COLOR_PAIR(CLR_BLUE));
        wattron(win, COLOR_PAIR(CLR_GRAY)); wprintw(win, " | "); wattroff(win, COLOR_PAIR(CLR_GRAY));
        wattron(win, COLOR_PAIR(items[i].color)); wprintw(win, "%s", items[i].label); wattroff(win, COLOR_PAIR(items[i].color));
    }
    wrefresh(win);
}

int do_login(WINDOW *win) {
    int attempts = 0;
    while (attempts < 3) {
        draw_banner(win);
        char user[64]={0}, pass[256]={0};
        wattron(win, COLOR_PAIR(CLR_GREEN)); mvwprintw(win, 10, 2, " Username: "); wattroff(win, COLOR_PAIR(CLR_GREEN));
        get_input(win, 10, 13, user, sizeof(user));
        wattron(win, COLOR_PAIR(CLR_GREEN)); mvwprintw(win, 11, 2, " Password: "); wattroff(win, COLOR_PAIR(CLR_GREEN));
        get_secret(win, 11, 13, pass, sizeof(pass));
        if (verify_password(user, pass)) {
            char logbuf[128]; snprintf(logbuf, sizeof(logbuf), "Login OK: %s", user);
            log_msg(logbuf); return 1;
        }
        attempts++;
        int left = 3 - attempts;
        wattron(win, COLOR_PAIR(CLR_RED));
        mvwprintw(win, 13, 2, " Acceso denegado. %s", left > 0 ? "Intentalo de nuevo." : "Bloqueado 60 segundos.");
        wattroff(win, COLOR_PAIR(CLR_RED));
        wrefresh(win);
        log_msg("Failed login attempt");
        sleep(left > 0 ? 2 : 60);
    }
    return 0;
}

WINDOW* sub_screen(const char *title) {
    WINDOW *win = newwin(LINES, COLS, 0, 0);
    keypad(win, TRUE);
    draw_banner(win);
    wattron(win, COLOR_PAIR(CLR_CYAN) | A_BOLD);
    mvwprintw(win, 9, 2, " >> %s", title);
    wattroff(win, COLOR_PAIR(CLR_CYAN) | A_BOLD);
    wattron(win, COLOR_PAIR(CLR_GRAY));
    mvwprintw(win, 10, 2, " ----------------------------------------------------------------");
    mvwprintw(win, LINES-2, 2, " [B] Volver al menu");
    wattroff(win, COLOR_PAIR(CLR_GRAY));
    wrefresh(win);
    return win;
}

void wait_b(WINDOW *win) {
    wattron(win, COLOR_PAIR(CLR_GRAY));
    mvwprintw(win, LINES-3, 2, " Presiona B para volver...");
    wattroff(win, COLOR_PAIR(CLR_GRAY));
    wrefresh(win);
    int ch;
    while ((ch = wgetch(win)) != 'b' && ch != 'B');
    delwin(win);
}

void opt_assign_interfaces() {
    WINDOW *win = sub_screen("Asignar Interfaces");
    char ifaces[256]={0};
    cmd_output("ifconfig -l", ifaces, sizeof(ifaces));
    wattron(win, COLOR_PAIR(CLR_WHITE)); mvwprintw(win, 12, 2, " Disponibles: %s", ifaces); wattroff(win, COLOR_PAIR(CLR_WHITE));
    wattron(win, COLOR_PAIR(CLR_GRAY));  mvwprintw(win, 13, 2, " (B para cancelar)"); wattroff(win, COLOR_PAIR(CLR_GRAY));
    char wan[32]={0}, lan[32]={0};
    wattron(win, COLOR_PAIR(CLR_YELLOW)); mvwprintw(win, 15, 2, " WAN: "); wattroff(win, COLOR_PAIR(CLR_YELLOW));
    if (get_input(win, 15, 8, wan, sizeof(wan))) { delwin(win); return; }
    wattron(win, COLOR_PAIR(CLR_YELLOW)); mvwprintw(win, 16, 2, " LAN: "); wattroff(win, COLOR_PAIR(CLR_YELLOW));
    if (get_input(win, 16, 8, lan, sizeof(lan))) { delwin(win); return; }
    if (strlen(wan) && strlen(lan)) {
        char cmd[512];
        snprintf(cmd, sizeof(cmd),
            NODE " -e \"const fs=require('fs'),f='%s';"
            "let d={};try{d=JSON.parse(fs.readFileSync(f,'utf8'))}catch(e){}"
            "d['%s']={role:'WAN',description:'Internet'};"
            "d['%s']={role:'LAN',description:'LAN'};"
            "fs.writeFileSync(f,JSON.stringify(d,null,2))\" 2>/dev/null",
            IFACES_FILE, wan, lan);
        system(cmd);
        system("pfctl -f /etc/pf.conf 2>/dev/null");
        wattron(win, COLOR_PAIR(CLR_GREEN)); mvwprintw(win, 18, 2, " OK - Listo."); wattroff(win, COLOR_PAIR(CLR_GREEN));
        log_msg("Interfaces assigned");
    }
    wait_b(win);
}

void opt_set_ip() {
    WINDOW *win = sub_screen("Configurar IP");
    char iface[32]={0}, ip[32]={0}, mask[32]={0}, gw[32]={0};
    wattron(win, COLOR_PAIR(CLR_GRAY)); mvwprintw(win, 12, 2, " (B en cualquier campo para cancelar)"); wattroff(win, COLOR_PAIR(CLR_GRAY));
    wattron(win, COLOR_PAIR(CLR_YELLOW)); mvwprintw(win, 13, 2, " Interfaz: "); wattroff(win, COLOR_PAIR(CLR_YELLOW));
    if (get_input(win, 13, 13, iface, sizeof(iface))) { delwin(win); return; }
    wattron(win, COLOR_PAIR(CLR_YELLOW)); mvwprintw(win, 14, 2, " IP:       "); wattroff(win, COLOR_PAIR(CLR_YELLOW));
    if (get_input(win, 14, 13, ip, sizeof(ip))) { delwin(win); return; }
    wattron(win, COLOR_PAIR(CLR_YELLOW)); mvwprintw(win, 15, 2, " Mascara:  "); wattroff(win, COLOR_PAIR(CLR_YELLOW));
    if (get_input(win, 15, 13, mask, sizeof(mask))) { delwin(win); return; }
    wattron(win, COLOR_PAIR(CLR_YELLOW)); mvwprintw(win, 16, 2, " Gateway:  "); wattroff(win, COLOR_PAIR(CLR_YELLOW));
    get_input(win, 16, 13, gw, sizeof(gw));
    if (strlen(iface) && strlen(ip) && strlen(mask)) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "ifconfig %s inet %s netmask %s 2>/dev/null", iface, ip, mask);
        system(cmd);
        snprintf(cmd, sizeof(cmd), "sysrc ifconfig_%s=\"inet %s netmask %s\" 2>/dev/null", iface, ip, mask);
        system(cmd);
        if (strlen(gw) && strcmp(gw,"b")!=0 && strcmp(gw,"B")!=0) {
            snprintf(cmd, sizeof(cmd), "route add default %s 2>/dev/null", gw);
            system(cmd);
        }
        system("pfctl -f /etc/pf.conf 2>/dev/null");
        wattron(win, COLOR_PAIR(CLR_GREEN)); mvwprintw(win, 18, 2, " OK - IP configurada."); wattroff(win, COLOR_PAIR(CLR_GREEN));
        log_msg("IP configured");
    }
    wait_b(win);
}

void opt_reset_password() {
    WINDOW *win = sub_screen("Resetear Contrasena Web UI");
    char np[256]={0}, cp[256]={0};
    wattron(win, COLOR_PAIR(CLR_GREEN)); mvwprintw(win, 12, 2, " Nueva contrasena: "); wattroff(win, COLOR_PAIR(CLR_GREEN));
    get_secret(win, 12, 21, np, sizeof(np));
    wattron(win, COLOR_PAIR(CLR_GREEN)); mvwprintw(win, 13, 2, " Confirmar:        "); wattroff(win, COLOR_PAIR(CLR_GREEN));
    get_secret(win, 13, 21, cp, sizeof(cp));
    if (strcmp(np, cp) == 0 && strlen(np)) {
        char cmd[1024];
        snprintf(cmd, sizeof(cmd),
            NODE " -e \"const fs=require('fs'),"
            "b=require('/opt/coltanos/backend/node_modules/bcrypt');"
            "b.hash(process.argv[1],10,function(e,h){"
            "let u=[];try{u=JSON.parse(fs.readFileSync('%s','utf8'))}catch(e){}"
            "const i=u.findIndex(function(x){return x.username==='admin';});"
            "if(i>=0)u[i].password=h;else u.push({id:1,username:'admin',password:h,role:'admin'});"
            "fs.writeFileSync('%s',JSON.stringify(u,null,2));})\" '%s' 2>/dev/null",
            USERS_FILE, USERS_FILE, np);
        system(cmd);
        wattron(win, COLOR_PAIR(CLR_GREEN)); mvwprintw(win, 15, 2, " OK - Contrasena actualizada."); wattroff(win, COLOR_PAIR(CLR_GREEN));
        log_msg("Web UI password reset");
    } else {
        wattron(win, COLOR_PAIR(CLR_RED)); mvwprintw(win, 15, 2, " ERROR: Las contrasenas no coinciden."); wattroff(win, COLOR_PAIR(CLR_RED));
    }
    wait_b(win);
}

void opt_ping() {
    WINDOW *win = sub_screen("Ping Host");
    char host[128]={0};
    wattron(win, COLOR_PAIR(CLR_GREEN)); mvwprintw(win, 12, 2, " Host (B=cancelar): "); wattroff(win, COLOR_PAIR(CLR_GREEN));
    if (get_input(win, 12, 22, host, sizeof(host))) { delwin(win); return; }
    if (strlen(host)) { char cmd[256]; snprintf(cmd, sizeof(cmd), "ping -c 4 %s 2>&1", host); wmove(win, 14, 0); run_cmd_win(cmd, win); }
    wait_b(win);
}

void opt_restart_services() {
    WINDOW *win = sub_screen("Reiniciar Servicios");
    struct { const char *name; const char *cmd; } svcs[] = {
        {"PF",       "pfctl -f /etc/pf.conf 2>/dev/null"},
        {"Unbound",  "service unbound restart 2>/dev/null"},
        {"Kea DHCP", "service kea onestart 2>/dev/null || service kea restart 2>/dev/null"},
        {"PM2/Node", "pm2 restart coltanos-backend 2>/dev/null"},
    };
    int y = 12;
    for (int i = 0; i < 4; i++) {
        wattron(win, COLOR_PAIR(CLR_WHITE)); mvwprintw(win, y, 2, " %-12s", svcs[i].name); wattroff(win, COLOR_PAIR(CLR_WHITE));
        wrefresh(win);
        int ret = system(svcs[i].cmd);
        wattron(win, COLOR_PAIR(ret == 0 ? CLR_GREEN : CLR_RED));
        wprintw(win, ret == 0 ? "[ OK ]" : "[ FAIL ]");
        wattroff(win, COLOR_PAIR(ret == 0 ? CLR_GREEN : CLR_RED));
        y++;
    }
    log_msg("Services restarted");
    wait_b(win);
}

void opt_reload_pf() {
    WINDOW *win = sub_screen("Recargar Firewall PF");
    wmove(win, 12, 0);
    run_cmd_win("pfctl -f /etc/pf.conf 2>&1", win);
    wattron(win, COLOR_PAIR(CLR_GREEN)); mvwprintw(win, LINES-5, 2, " OK - Firewall recargado."); wattroff(win, COLOR_PAIR(CLR_GREEN));
    log_msg("PF reloaded");
    wait_b(win);
}

void opt_update() {
    WINDOW *win = sub_screen("Actualizar Coltan OS");
    wattron(win, COLOR_PAIR(CLR_YELLOW)); mvwprintw(win, 12, 2, " Verificando..."); wattroff(win, COLOR_PAIR(CLR_YELLOW));
    wrefresh(win);
    system("cd /opt/coltanos && git fetch origin 2>/dev/null");
    char local[64]={0}, remote[64]={0};
    cmd_output("cd /opt/coltanos && git rev-parse --short HEAD 2>/dev/null", local, sizeof(local));
    cmd_output("cd /opt/coltanos && git rev-parse --short origin/main 2>/dev/null", remote, sizeof(remote));
    if (strcmp(local, remote) == 0) {
        wattron(win, COLOR_PAIR(CLR_GREEN)); mvwprintw(win, 14, 2, " OK - Actualizado (%s)", local); wattroff(win, COLOR_PAIR(CLR_GREEN));
    } else {
        wattron(win, COLOR_PAIR(CLR_YELLOW));
        mvwprintw(win, 14, 2, " Disponible: %s -> %s", local, remote);
        mvwprintw(win, 15, 2, " Aplicar? [s/N]: ");
        wattroff(win, COLOR_PAIR(CLR_YELLOW));
        char ans[4]={0};
        get_input(win, 15, 19, ans, sizeof(ans));
        if (ans[0]=='s'||ans[0]=='S'||ans[0]=='y'||ans[0]=='Y') {
            wmove(win, 17, 0);
            run_cmd_win("cd /opt/coltanos && git pull origin main 2>&1", win);
            system("pm2 restart coltanos-backend 2>/dev/null");
            wattron(win, COLOR_PAIR(CLR_GREEN)); mvwprintw(win, LINES-5, 2, " OK - Actualizado."); wattroff(win, COLOR_PAIR(CLR_GREEN));
            log_msg("System updated");
        }
    }
    wait_b(win);
}

void opt_shell() {
    WINDOW *win = sub_screen("Shell de Administracion");
    char pass[256]={0};
    wattron(win, COLOR_PAIR(CLR_RED));   mvwprintw(win, 12, 2, " ADVERTENCIA: Acceso de alto nivel."); wattroff(win, COLOR_PAIR(CLR_RED));
    wattron(win, COLOR_PAIR(CLR_GREEN)); mvwprintw(win, 13, 2, " Contrasena: "); wattroff(win, COLOR_PAIR(CLR_GREEN));
    wrefresh(win);
    get_secret(win, 13, 15, pass, sizeof(pass));
    if (verify_system_user("root", pass)) {
        log_msg("Shell access granted");
        def_prog_mode();
        endwin();
        printf("\n Acceso concedido. Escribe 'exit' para volver.\n\n");
        system("/bin/sh");
        reset_prog_mode();
        refresh();
        log_msg("Shell session ended");
    } else {
        wattron(win, COLOR_PAIR(CLR_RED)); mvwprintw(win, 15, 2, " ACCESO DENEGADO."); wattroff(win, COLOR_PAIR(CLR_RED));
        log_msg("FAILED shell access");
        wrefresh(win); sleep(3);
    }
    delwin(win);
}

void opt_credits() {
    WINDOW *win = sub_screen("Info / Creditos");
    wattron(win, COLOR_PAIR(CLR_CYAN) | A_BOLD);
    mvwprintw(win, 12, 2, " Coltan OS v%s", VERSION);
    mvwprintw(win, 13, 2, " Network Security OS basado en FreeBSD");
    wattroff(win, COLOR_PAIR(CLR_CYAN) | A_BOLD);
    wattron(win, COLOR_PAIR(CLR_WHITE));
    mvwprintw(win, 15, 2, " Desarrollado por: Enrique Molina");
    mvwprintw(win, 16, 2, " Email:            enriquefmolina@gmail.com");
    wattroff(win, COLOR_PAIR(CLR_WHITE));
    wait_b(win);
}

int main() {
    initscr();
    start_color();
    cbreak();
    noecho();
    curs_set(0);
    keypad(stdscr, TRUE);

    init_pair(CLR_GREEN,  COLOR_GREEN,  COLOR_BLACK);
    init_pair(CLR_CYAN,   COLOR_CYAN,   COLOR_BLACK);
    init_pair(CLR_YELLOW, COLOR_YELLOW, COLOR_BLACK);
    init_pair(CLR_RED,    COLOR_RED,    COLOR_BLACK);
    init_pair(CLR_GRAY,   COLOR_WHITE,  COLOR_BLACK);
    init_pair(CLR_WHITE,  COLOR_WHITE,  COLOR_BLACK);
    init_pair(CLR_BLUE,   COLOR_BLUE,   COLOR_BLACK);

    WINDOW *main_win = newwin(LINES, COLS, 0, 0);
    keypad(main_win, TRUE);

    while (1) {
        if (!do_login(main_win)) continue;
        int logout = 0;
        while (!logout) {
            wclear(main_win);
            draw_banner(main_win);
            draw_sysinfo(main_win, 9);
            draw_menu(main_win, 18);
            wattron(main_win, COLOR_PAIR(CLR_GREEN));
            mvwprintw(main_win, LINES-2, 2, " Opcion: ");
            wattroff(main_win, COLOR_PAIR(CLR_GREEN));
            wrefresh(main_win);
            curs_set(1);
            int ch = wgetch(main_win);
            curs_set(0);
            switch(ch) {
                case '1': opt_assign_interfaces(); break;
                case '2': opt_set_ip(); break;
                case '3': opt_reset_password(); break;
                case '4': opt_ping(); break;
                case '5': opt_restart_services(); break;
                case '6': opt_reload_pf(); break;
                case '7': opt_update(); break;
                case '8': {
                    WINDOW *w = sub_screen("Reiniciar Sistema");
                    wattron(w, COLOR_PAIR(CLR_YELLOW)); mvwprintw(w, 12, 2, " Reiniciar? [s/N]: "); wattroff(w, COLOR_PAIR(CLR_YELLOW));
                    wrefresh(w); char a[4]={0}; get_input(w, 12, 21, a, sizeof(a));
                    if (a[0]=='s'||a[0]=='S'||a[0]=='y'||a[0]=='Y') { log_msg("Reboot"); endwin(); system("reboot"); }
                    delwin(w); break;
                }
                case '9': {
                    WINDOW *w = sub_screen("Apagar Sistema");
                    wattron(w, COLOR_PAIR(CLR_RED)); mvwprintw(w, 12, 2, " Apagar? [s/N]: "); wattroff(w, COLOR_PAIR(CLR_RED));
                    wrefresh(w); char a[4]={0}; get_input(w, 12, 18, a, sizeof(a));
                    if (a[0]=='s'||a[0]=='S'||a[0]=='y'||a[0]=='Y') { log_msg("Shutdown"); endwin(); system("shutdown -p now"); }
                    delwin(w); break;
                }
                case '0': opt_shell(); break;
                case 'c': case 'C': log_msg("Logout"); logout = 1; break;
                case 'i': case 'I': opt_credits(); break;
            }
        }
    }
    endwin();
    return 0;
}