#import <Foundation/Foundation.h>
@protocol Greeter <NSObject>
- (NSString *)greet:(NSString *)name;
@optional
+ (instancetype)shared;
@end
@interface Person : NSObject <Greeter>
@property (nonatomic, copy) NSString *name;
@property (nonatomic, assign, readonly) NSInteger age;
- (instancetype)initWithName:(NSString *)name;
@end
@implementation Person
- (instancetype)initWithName:(NSString *)name { if ((self = [super init])) { _name = [name copy]; _age = 30; } return self; }
- (NSString *)greet:(NSString *)name { return [NSString stringWithFormat:@"Hi %@ from %@", name, _name]; }
+ (instancetype)shared { static Person *p; if (!p) p = [[Person alloc] initWithName:@"shared"]; return p; }
@end
@interface Person (Loud)
- (NSString *)shout;
@end
@implementation Person (Loud)
- (NSString *)shout { return [self.name uppercaseString]; }
@end
int main(void) { @autoreleasepool { NSLog(@"%@", [[Person shared] greet:@"moex"]); NSLog(@"%@", [[Person shared] shout]); } return 0; }
