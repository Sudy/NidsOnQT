#ifndef NIDSTHREAD_H
#define NIDSTHREAD_H
#include <QThread>

class NidsThread : public QThread
{
public:
    NidsThread();
    void run();
};

#endif // NIDSTHREAD_H
