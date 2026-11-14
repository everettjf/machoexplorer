// Root class, category with class property, protocols; no Foundation needed.
__attribute__((objc_root_class))
@interface Base
+ (id)alloc;
@property (nonatomic) int value;
@property (class, nonatomic, readonly) int sharedCount;
@end
@protocol Walker
- (void)walk;
@optional
+ (int)legs;
@property (nonatomic, readonly) int speed;
@end
@protocol Runner <Walker>
- (void)run:(int)distance;
@end
@interface Animal : Base <Runner> { @public int _age; double _weight; }
@property (nonatomic, copy) id name;
@end
@interface Base (Extras) <Walker>
@property (class, nonatomic, readonly) int extraClassProp;
@property (nonatomic, readonly) int extraProp;
- (int)twice;
+ (int)classTwice;
@end
@interface Animal (Sounds)
- (void)bark;
@end
static int counter;
@implementation Base
+ (id)alloc { return (id)0; }
+ (int)sharedCount { return counter; }
@end
@implementation Animal
- (void)walk {}
- (void)run:(int)distance { _age += distance; }
@end
@implementation Base (Extras)
+ (int)extraClassProp { return 7; }
- (int)extraProp { return 8; }
- (int)twice { return self.value * 2; }
+ (int)classTwice { return 2; }
- (void)walk {}
@end
@implementation Animal (Sounds)
- (void)bark {}
@end
int main(void) { return [Base sharedCount]; }
