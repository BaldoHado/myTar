#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <utime.h>
#include <dirent.h>
#include "mytar.h"
#include <pwd.h>
#include <grp.h>
#include <time.h>
#define BLOCK_SIZE 512
#define MAX_NAME 100
#define MAX_MODE 8
#define MAX_UID 8
#define MAX_GID 8
#define MAX_SIZE 12
#define MAX_MTIME 12
#define MAX_CHKSUM 8
#define MAX_TYPEFLAG 1
#define MAX_LINKNAME 100
#define MAX_MAGIC 6
#define MAX_VERSION 2
#define MAX_UNAME 32
#define MAX_GNAME 32
#define MAX_PREFIX 155
#define MAX_PERMISSIONS 10
#define MAX_OWNERS 17
#define MAX_LISTSIZE 8
#define MAX_LISTMTIME 16


uint32_t extract_special_int(char *where, int len) {
    int32_t val= -1;
        if ( (len >= sizeof(val)) && (where[0] & 0x80)) {
        val = *(int32_t *)(where+len-sizeof(val));
        val = ntohl(val); 
    }
    return val;
}


int insert_special_int(char *where, size_t size, int32_t val) {
    int err=0;
    if ( val < 0 || ( size < sizeof(val)) ) {
        err++;
    } else {
        memset(where, 0, size);
        *(int32_t *)(where+size-sizeof(val)) = htonl(val);
        *where |= 0x80;
    }
    return err;
}

//  Function that separates name and prefix of a path
//  and puts it in name , prefix buffers
int name_overflow(char *name, char *prefix, char *path){
    unsigned int overflow = strlen(path) - MAX_NAME;
    int i;
    int j = 0;
    if (name == NULL || prefix == NULL) {
        return -1;
    }
    for (i = 0; i < overflow || path[i] != '/'; i++) {
        prefix[i] = path[i];
    }
    // Is there space for a null terminator?
    if (i <= MAX_PREFIX) {
        // i++ to skip the slash separating the name and prefix
        prefix[i++] = '\0';
    }
    while (path[i] != '\0') {
        name[j++] = path[i++];
    }
    // Is there space for a null terminator?
    if (j <= MAX_NAME) {
        name[j] = '\0';
    }
    return 1;
}

// Write the contents of a file 
int write_contents(int fdin, int fdout){
    char buff[BLOCK_SIZE];
    ssize_t num;
    ssize_t bytesWritten = 0;
    memset(buff, 0, BLOCK_SIZE);
    while ((num = read(fdin, buff, BLOCK_SIZE)) > 0){
        if ((bytesWritten = write(fdout, buff, num)) < 0){
            perror("Failed to write contents");
            return -1;
        }
        memset(buff, 0, BLOCK_SIZE);
    }
    if (num != 0) {
        perror("Failed to read contents");
        return -1;
    }
    if (BLOCK_SIZE - bytesWritten != 0) {
        if (-1 == write(fdout, buff, (BLOCK_SIZE - bytesWritten))){
            perror("Failed to write contents");
            return -1;
        }
    }
    return 1;
}

// Write the header of a file
int write_header(int fd, char *path) {
    struct header *hd = malloc(sizeof(struct header));
    struct stat sb; 
    struct passwd *pb;
    struct group *gb;
    int i;
    unsigned int sum = 0;
    int fdin;
    memset(hd, 0, sizeof(struct header));
    if (hd == NULL) {
        perror("Malloc Error");
        return -1;
    }
    if (-1 == lstat(path, &sb)) {
        perror("Lstat Error");
        return -1;
    }
    if (strlen(path) > MAX_NAME) {
        if (strlen(path) > PATH_MAX){
            perror("Path too long");
            return -1;
        }
        char *nameBuff = malloc(MAX_NAME);
        char *prefixBuff = malloc(MAX_PREFIX);
        if (nameBuff == NULL || prefixBuff == NULL) {
            perror("Malloc error");
            return -1;
        }
        memset(nameBuff, 0, MAX_NAME);
        memset(prefixBuff, 0, MAX_PREFIX);
        name_overflow(nameBuff, prefixBuff, path);
        strcpy(hd->name, nameBuff);
        strcpy(hd->prefix, prefixBuff);
        free(nameBuff);
        free(prefixBuff);
    } else {
        strcpy(hd->name, path);
    }
    sprintf(hd->mode, "%07o", sb.st_mode & 07777);
    if (sb.st_uid > 07777777) {
        insert_special_int(hd->uid, MAX_UID, sb.st_uid);
    } else {
        sprintf(hd->uid, "%07o", sb.st_uid);
    }
    if (sb.st_gid > 07777777) {
        insert_special_int(hd->gid, MAX_GID, sb.st_gid);
    } else {
        sprintf(hd->gid, "%07o", sb.st_gid);
    }
    if (S_ISDIR(sb.st_mode) || S_ISLNK(sb.st_mode)){
        sprintf(hd->size, "%011o", 0);
    } else {
        sprintf(hd->size, "%011o", (int)sb.st_size);
    }
    sprintf(hd->mtime, "%011o", (int)sb.st_mtime);
    if (S_ISDIR(sb.st_mode)) {
        hd->typeflag[0] = '5';
    } else if (S_ISLNK(sb.st_mode)){
        hd->typeflag[0] = '2';
    } else {
        hd->typeflag[0] = '0';
    }

    if (S_ISLNK(sb.st_mode)) {
        if (-1 == readlink(path, hd->linkname, MAX_LINKNAME - 1)){
            perror("Readlink Error");
            return -1;
        };
        hd->linkname[MAX_LINKNAME] = '\0';
    }
    strcpy(hd->magic, "ustar");
    strcpy(hd->version, "00");
    if (NULL == (pb = getpwuid(sb.st_uid))) {
        perror("Getpwuid Error");
        return -1;
    }  
    if (NULL == (gb = getgrgid(sb.st_gid))) {
        perror("Getgrgid Error");
        return -1;
    }    
    strcpy(hd->uname, pb->pw_name);
    strcpy(hd->gname, gb->gr_name);
    memset(hd->chksum, ' ', MAX_CHKSUM);
    for (i = 0; i < BLOCK_SIZE; i++) {
        sum += (unsigned char)((unsigned char*)hd)[i];
    }
    sprintf(hd->chksum, "%07o",  sum);
    if (-1 == write(fd, hd, BLOCK_SIZE)) {
        perror("Write Error");
        return -1;
    }

    if (-1 == (fdin = open(path, O_RDONLY))){
        perror("File Open Error");
        return -1;
    }
    if (!S_ISDIR(sb.st_mode) && sb.st_size > 0){
        if (-1 == write_contents(fdin, fd)) {
            perror("Failure to write contents of header");
            return -1;
        }
    }
    
    free(hd);
    return 1;
    
}

// Preorder traversal of the directory tree
int preorder(char *path, int fd, int verbose){
    DIR *cur;
    struct dirent *entry;
    if (NULL == (cur = opendir(path))){
        perror("Cannot open current directory");
        return -1;
    } 

    while (NULL != (entry = readdir(cur))){
        struct stat tempSb;
        char temp_path[PATH_MAX];
        snprintf(temp_path, PATH_MAX, "%s%s", path, entry->d_name);
        // Skip . and .. 
        if (!strcmp(entry->d_name, ".")|| !strcmp(entry->d_name, "..")){
            continue;
        }
        if (-1 == lstat(temp_path, &tempSb)) {
            perror("Failed to stat directory");
            return -1;
        }
        // Directories need a slash after their name
        if(S_ISDIR(tempSb.st_mode)){
            snprintf(temp_path, PATH_MAX, "%s%s/", path, entry->d_name);
        }
        if (-1 == write_header(fd, temp_path)) {
            perror("Error writing header");
        }
        if (S_ISDIR(tempSb.st_mode)) {
            if (verbose) {
                printf("%s\n", temp_path);
            }
            preorder(temp_path, fd, verbose);
        } else {
            if (verbose) {
                printf("%s%s\n", path, entry->d_name);
            }
        }
    }   
    closedir(cur);
    return 1;
}

// Main function for archive creation  
int createArchive(char *path, int tarFd, int verbose){
    struct stat pathStat; 
    if (-1 == lstat(path, &pathStat)) {
        perror("Stat Error");
        return -1;
    }
    if (!S_ISDIR(pathStat.st_mode)) {
        if (-1 == write_header(tarFd, path)){
            perror("Error writing header");
            return -1;
        }
        return 1;
    }
    strcat(path, "/");
    if (verbose){
        printf("%s\n", path);
    }
    if (-1 == write_header(tarFd, path)){
        perror("Error writing header");
    }
    preorder(path, tarFd, verbose);    
    return 1;
}

// Verify that the checksum is valid with the given header
unsigned int verify_checksum(struct header *hd) {
    unsigned int sum = 0;
    char tempChkSum[MAX_CHKSUM];
    int i;
    strcpy(tempChkSum, hd->chksum);
    memset(hd->chksum, ' ', MAX_CHKSUM);
    for (i = 0; i < BLOCK_SIZE; i++) {
        sum += (unsigned char)((unsigned char*)hd)[i];
    }
    // If the sum was just the sum of the spaces set above, 
    // then the sum is really just zero
    if (sum == 256) {
        sum = 0;
    }
    strcpy(hd->chksum, tempChkSum);
    return sum;
}

// Main function for reading an archive
int readArchive (int fd, char *exPath, int verbose) {
    struct header *hd = malloc(BLOCK_SIZE);
    int readBytes = 0;
    if (hd == NULL){
        perror("Malloc error");
        return -1;
    }
    memset(hd, 0, BLOCK_SIZE);
    while ((readBytes = read(fd, hd, BLOCK_SIZE)) > 0) {
        unsigned int perms = strtol(hd->mode, NULL, 8);
        char path[PATH_MAX];
        unsigned int fSize = strtol(hd->size, NULL, 8);
        unsigned int amtBlocks;
        unsigned int checkSum = strtol(hd->chksum, NULL, 8);
        memset(path, 0, PATH_MAX);
        
        if (hd->prefix[0]) {
           snprintf(path,  PATH_MAX, "%.155s/%.100s", hd->prefix, hd->name);
        } else {
            strncpy(path, hd->name, MAX_NAME);
        }

        if (exPath && strncmp(path, exPath, strlen(exPath))) {
            continue;
        } 
        if (verify_checksum(hd) != checkSum) {
            perror("checkSum Error");
            free(hd);
            return -1;
        } 
        if (checkSum == 0){
            unsigned int checkSum2;
            if (-1 == read(fd, hd, BLOCK_SIZE)){
                perror("Read Error");
                free(hd);
                return -1;
            }
            if (0 == (checkSum2 = strtol(hd->chksum, NULL, 8))){
                // Two null blocks detected, return
                free(hd);
                return 1;
            } else {
                lseek(fd, -512, SEEK_CUR);
            }
        }
        if (strncmp(hd->magic, "ustar", MAX_MAGIC-1) != 0) {
            perror("Invalid tar file");
            free(hd);
            return -1;
        }

        amtBlocks = (unsigned int)ceil((double)fSize / BLOCK_SIZE);
        lseek(fd, amtBlocks*BLOCK_SIZE, SEEK_CUR);
        
        if (verbose) {
            int permIdx = MAX_PERMISSIONS-1;
            time_t curTime = (time_t)strtol(hd->mtime, NULL, 8);
            struct tm *time;
            char tFlag = hd->typeflag[0];
            char permissions[MAX_PERMISSIONS+1];
            char listMTime[MAX_LISTMTIME+1];
            char owners[MAX_OWNERS+1];
            strcpy(permissions, "-rwxrwxrwx");
            permissions[0] =tFlag =='5' ? 'd' : (tFlag == '2' ? 'l' : '-');
            while (permIdx > 0) {
                if ((perms & 1) == 0) {
                    permissions[permIdx] = '-';
                }
                perms >>= 1;
                permIdx--;
            }
            permissions[10] = '\0';
            time = localtime(&curTime);
            if (hd->uname[0] == 0x80) {
                uint32_t spec_int = extract_special_int(hd->uname, 8);
                snprintf(owners, MAX_OWNERS+1, "%zu/%s", spec_int, hd->gname); 
            } else {
                snprintf(owners, MAX_OWNERS+1, "%s/%s", hd->uname, hd->gname);
            }
            
            strftime(listMTime, MAX_LISTMTIME+1, "%Y-%m-%d %H:%M", time);
            printf("%.10s %.17s ", permissions, owners);
            printf("%u %.16s %.256s\n", fSize, listMTime, path);
        } else {
            printf("%.256s\n", path);
        }
        memset(hd, 0, BLOCK_SIZE);
    }
    if (readBytes != 0){
        free(hd);
        perror("Read error");
        return -1;
    }
    free(hd);
    lseek(fd, 0, SEEK_SET);
    return 1;
}

// Creates all directories in its path
int createDirectories(const char *path) {
    char *dup_path = strdup(path);
    char *curDir = strtok(dup_path, "/");
    char cPath[PATH_MAX];
    strcpy(cPath, curDir);
    int len = strlen(curDir);

    while (curDir != NULL) {
        if (mkdir(cPath, 0777) == -1) {
            perror("mkdir");
            free(dup_path);
            return -1;
        }
        curDir = strtok(NULL, "/");
        if (curDir != NULL) {
            cPath[len] = '/';
            cPath[len + 1] = '\0';
            strcat(cPath, curDir);
            len = strlen(cPath);
        }
    }

    free(dup_path);
    return 1;
}

//Main function for extracting an archive
int extractArchive(int fd, char *exPath, int strict, int verbose) { 
    struct header *hd = malloc(BLOCK_SIZE);
    int readBytes = 0;
    if (hd == NULL){
        perror("malloc");
        return -1;
    }
    memset(hd, 0, BLOCK_SIZE);
    while ((readBytes = read(fd, hd, BLOCK_SIZE)) > 0) {
        unsigned int perms = strtol(hd->mode, NULL, 8);
        int hasExecutePerm = 0;
        int bitShift;
        char path[PATH_MAX];
        memset(path, 0, PATH_MAX);
        if (hd->prefix[0] != '\0') {
            strncpy(path, hd->prefix, MAX_PREFIX);
            strcat(path, "/");
            strcat(path, hd->name);
        } else {
            strncpy(path, hd->name, MAX_NAME);
        }
        if (exPath && strncmp(path, exPath, strlen(exPath))) {
            continue;
        } 
        if (verbose) {
            printf("%s\n", path);
        }
        // Dirs automatically get execute perms
        if (hd->typeflag[0] == '5') {
            hasExecutePerm = 1;
        } else {
            // Checks if execute permission is set for usr, grp, oth
            // BitShift -= 3 because rwx is 3 bits
            for (bitShift = 6; bitShift >= 0; bitShift -= 3) { 
                if ((perms >> bitShift) & 1) {
                    hasExecutePerm = 1;
                    break;
                }
            }
        }
    
        if (hd->typeflag[0] == '5') {
            mkdir(path, hasExecutePerm ? 0777 : 0666);
        } else if (hd->typeflag[0] == '2') {
            symlink(hd->linkname, path);
        } else {
            int tempFd;
            unsigned int fSize = strtol(hd->size, NULL, 8);
            unsigned int amtBlk =(unsigned int)ceil((double)fSize / BLOCK_SIZE);
            unsigned int rmd = fSize % BLOCK_SIZE; 
            char buf[BLOCK_SIZE];
            int i;
            unsigned int checkSum = strtol(hd->chksum, NULL, 8);
            if (checkSum == 0){
                unsigned int checkSum2;
                if (-1 == read(fd, hd, BLOCK_SIZE)){
                    perror("Read error");
                    free(hd);
                    return -1;
                }
                if (0 == (checkSum2 = strtol(hd->chksum, NULL, 8))){
                    // Two null blocks detected, return
                    free(hd);
                    return 1;
                } else {
                    lseek(fd, -BLOCK_SIZE, SEEK_CUR);
                }
            } else {
                struct utimbuf newTime;
                struct stat newFile;
                time_t modTime = (time_t)strtol(hd->mtime, NULL, 8);
                if (verify_checksum(hd) != checkSum) {
                    perror("checkSum Error");
                    free(hd);
                    return -1;
                } 
                if (strict) {
                    if (strncmp(hd->magic, "ustar\0", MAX_MAGIC) != 0){
                        perror("Magic");
                        free(hd);
                        return -1;
                    }
                    if (strncmp(hd->version, "00", MAX_VERSION) != 0) {
                        perror("Version");
                        free(hd);
                        return -1;
                    }
                } else {
                    if (strncmp(hd->magic, "ustar", MAX_MAGIC-1) != 0){
                        perror("Magic");
                        free(hd);
                        return -1;
                    }
                }
                if (-1 == creat(path, hasExecutePerm ? 0777 : 0666)) {
                    // Creat will fail when the directories
                    // before it don't exist
                    // This happens when a file/dir is 
                    // named that is depeer in the tree
                    // Thus, the previous directories 
                    // before it need to be created
                    char dirPath[PATH_MAX];
                    strcpy(dirPath, path);
                    char *pathFileName = strrchr(dirPath, '/');
                    if (pathFileName != NULL) {
                        *pathFileName = '\0';
                    }

                    if (createDirectories(dirPath) == -1) {
                        perror("error creating dirs");
                        free(hd);
                        return -1;
                    }
                    if (-1 == creat(path, hasExecutePerm ? 0777 : 0666)) {
                        perror("creat");
                        free(hd);
                        return -1;
                    }
                }
                if (-1 == lstat(path, &newFile)){
                    perror("stat");
                    free(hd);
                    return -1;
                }
                newTime.modtime = modTime;
                newTime.actime = newFile.st_atime;
                if (-1 == utime(path, &newTime)){
                    perror("utime");
                    free(hd);
                    return -1;
                }
                if (-1 == (tempFd = open(path, O_WRONLY))){
                    perror("open");
                    free(hd);
                    return -1;
                }
                for (i = 0; i < amtBlk; i++) {
                    int bytes = 0;
                    if (-1 == (bytes = read(fd, buf, BLOCK_SIZE))) {
                        perror("read");
                        free(hd);
                        return -1;
                    }
                    if (-1==write(tempFd, buf, i == amtBlk - 1 ? rmd : bytes)){
                        perror("write");
                        free(hd);
                        return -1;
                    }
                }
            }
        }
        memset(hd, 0, BLOCK_SIZE);
    }
    if (readBytes != 0){
        perror("Read error");
        free(hd);
        return -1;
    }
    free(hd);
    lseek(fd, 0, SEEK_SET);
    return 1;
}

int main(int argc, char *argv[]){
    if (argc < 3){
        perror("Not enough arguments");
        return 1;
    }

    
    int i;
    int verbose = 0;
    int fSet = 0;
    int extract = 0;
    int create = 0;
    int strict = 0;
    int list = 0;
    int optionSelected = 0;
    char buff[BLOCK_SIZE];
    memset(buff, 0, BLOCK_SIZE);
    int tarFd;
    for (i = 0; i < strlen(argv[1]); i++) {
        if (argv[1][i] == 'v'){ 
            verbose = 1;
        } else if (argv[1][i] == 'f'){ 
            fSet = 1;
        } else if (argv[1][i] == 'x'){ 
            extract = 1;
            optionSelected = 1;
        } else if (argv[1][i] == 'c'){ 
            create = 1;
            optionSelected = 1;
        } else if  (argv[1][i] == 'S'){ 
            strict = 1;
        } else if  (argv[1][i] == 't'){ 
            list = 1;
            optionSelected = 1;
        } else {
            perror("Invalid option selected");
            return 1;
        }
    }
    if (optionSelected == 0){
        perror("No option selected");
        return 1;
    }
    if (optionSelected > 1){
        perror("Cannot select multiple options");
        return 1;
    }
    if (!fSet || !argv[2]) {
        perror("Must specify an archive filename");
        return 1;
    }
    if (create) {
        int j;
        int amtPaths = argc - 3;
        if (-1 == (tarFd = open(argv[2], O_RDWR | O_CREAT | O_TRUNC, 0666))) {
            perror("open file");
            return 1;
        }
        for (j = 0; j < amtPaths; j++) {
            char *pathCopy = malloc(strlen(argv[3+j])+1);
            if (pathCopy == NULL) {
                perror("malloc");
                return 1;
            }
            strcpy(pathCopy, argv[3+j]);
            if (-1 == createArchive(pathCopy, tarFd, verbose)) {
                perror("Error creating archive");
            }

            free(pathCopy);
        }
        if (-1 == write(tarFd, buff, BLOCK_SIZE)){
            perror("write");
            return 1;
        }
        if (-1 == write(tarFd, buff, BLOCK_SIZE)){
            perror("write");
            return 1;
        }
        close(tarFd);
    }
    if (extract) {
        int fd = open(argv[2], O_RDONLY);
        int amtPaths = argc - 3;
        int j;
        if (fd == -1){
            perror("open");
            return 1;
        }
        if (amtPaths == 0) {
            if (-1 == extractArchive(fd, argv[3], strict, verbose)) {
                perror("Error extracting archive");
            }
        } else {
            for (j = 0; j < amtPaths; j++) {
                char *pathCopy = malloc(strlen(argv[3+j]));
                if (pathCopy == NULL) {
                    perror("malloc");
                    return 1;
                }
                strcpy(pathCopy, argv[3+j]);
                if (-1 == extractArchive(fd, pathCopy, strict, verbose)) {
                    perror("Error extracting archive");
                }
                free(pathCopy);
            }
        
        }
        
        close(fd);
    }
    if (list) {
        int fd = open(argv[2], O_RDONLY);
        int j;
        int amtPaths = argc - 3;
        if (fd == -1){
            perror("open");
            return 1;
        }
        if (amtPaths == 0) {
            if (-1 == readArchive(fd, NULL, verbose)){
                perror("Error reading archive");
            }
        } else {
            for (j = amtPaths-1; j >= 0; j--) {
                if (-1 == readArchive(fd, argv[3+j], verbose)){
                    perror("Error reading archive");
                }
            }
        }
        close(fd);
    }

    
    
    return 0;
}