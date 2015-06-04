/* 
 * File:   data.h
 * Author: donizyo
 *
 * Created on June 4, 2015, 7:28 PM
 */

#ifndef DATA_H
#define	DATA_H

#ifdef	__cplusplus
extern "C" {
#endif

    struct String {
        unsigned int hash;
        int len;
        unsigned char str[];
    };

    struct String *createString(int);
    void releaseString(struct String *);
    unsigned int hashCode(struct String *);

#ifdef	__cplusplus
}
#endif

#endif	/* DATA_H */

