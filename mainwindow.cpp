#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "nidsform.h"
#include "formrule.h"



MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    QTabWidget* pTableWidget = ui->tabWidget;
   // pTableWidget->
    pTableWidget->addTab (new NidsForm(),"Intrusion Detection");
    pTableWidget->addTab (new FormRule(),"Rule Information");


}

MainWindow::~MainWindow()
{

    delete ui;
}
