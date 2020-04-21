//
//  ViewController.m
//  fishhookTest
//
//  Created by tongleiming on 2019/7/3.
//  Copyright © 2019 tongleiming. All rights reserved.
//

#import "ViewController.h"
#import "fishhook/fishhook.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    NSLog(@"我还没被绑定");
    NSLog(@"我不是个老司机");
    
    //rebinding结构体
    struct rebinding nslog;
    nslog.name = "NSLog";
    // 替换的函数
    nslog.replacement = myNslog;
    // 保存原始的被替换的函数
    nslog.replaced = (void *)&sys_nslog;
    
    //rebinding结构体数组
    struct rebinding rebs[1] = {nslog};
    /*
     * 存放rebinding结构体的数组
     * 数组的长度
     */
    rebind_symbols(rebs, 1);
}
// 函数指针
static void(*sys_nslog)(NSString * format, ...);
// 定义一个新的函数
void myNslog(NSString * format, ...) {
    format = [format stringByAppendingString:@"勾上了! \n"];
    // 调用原始的
    sys_nslog(format);
}

- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event {
    NSLog(@"点击了屏幕!");
}


@end
