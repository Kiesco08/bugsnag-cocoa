//
//  BugsnagStacktrace.m
//  Bugsnag
//
//  Created by Jamie Lynch on 06/04/2020.
//  Copyright © 2020 Bugsnag. All rights reserved.
//

#import "BugsnagStacktrace.h"

#import "BSG_KSBacktrace.h"
#import "BSG_KSDynamicLinker.h"
#import "BugsnagKeys.h"
#import "BugsnagLogger.h"
#import "BugsnagStackframe.h"

@interface BugsnagStackframe ()
+ (BugsnagStackframe *)frameFromDict:(NSDictionary *)dict
                          withImages:(NSArray *)binaryImages;
- (NSDictionary *)toDictionary;
+ (instancetype)frameFromJson:(NSDictionary *)json;
@end

@interface BugsnagStacktrace ()
@property NSMutableArray<BugsnagStackframe *> *trace;
@end

@implementation BugsnagStacktrace

+ (instancetype)stacktraceFromJson:(NSDictionary *)json {
    BugsnagStacktrace *trace = [BugsnagStacktrace new];
    NSMutableArray *data = [NSMutableArray new];

    if (json != nil) {
        for (NSDictionary *dict in json) {
            BugsnagStackframe *frame = [BugsnagStackframe frameFromJson:dict];

            if (frame != nil) {
                [data addObject:frame];
            }
        }
    }
    trace.trace = data;
    return trace;
}

- (instancetype)initWithTrace:(NSArray<NSDictionary *> *)trace
                 binaryImages:(NSArray<NSDictionary *> *)binaryImages {
    if (self = [super init]) {
        self.trace = [NSMutableArray new];

        for (NSDictionary *obj in trace) {
            BugsnagStackframe *frame = [BugsnagStackframe frameFromDict:obj withImages:binaryImages];

            if (frame != nil && [self.trace count] < 200) {
                [self.trace addObject:frame];
            }
        }
    }
    return self;
}

- (instancetype)initWithCallStackSymbols:(NSArray<NSString *> *)callStackSymbols {
    if (!(self = [super init])) {
        return nil;
    }
    
    NSError *error;
    NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:@"(0x[0-9a-fA-F]+)" options:0 error:&error];
    if (!regex) {
        bsg_log_err(@"%@", error);
        return nil;
    }
    
    uintptr_t *addresses = calloc(callStackSymbols.count, sizeof(uintptr_t));
    Dl_info *infos = calloc(callStackSymbols.count, sizeof(Dl_info));
    int numEntries = 0;
    
    for (NSString *string in callStackSymbols) {
        NSTextCheckingResult *match = [regex firstMatchInString:string options:0 range:NSMakeRange(0, [string length])];
        if (match.numberOfRanges != 2) {
            continue;
        }
        NSString *addressHex = [string substringWithRange:[match rangeAtIndex:1]];
        unsigned long long address = 0;
        if ([[NSScanner scannerWithString:addressHex] scanHexLongLong:&address]) {
            addresses[numEntries] = address;
            numEntries ++;
        }
    }
    
    bsg_ksbt_symbolicate(addresses, infos, numEntries, 0);

    NSMutableArray<BugsnagStackframe *> *frames = [NSMutableArray arrayWithCapacity:numEntries];
    for (int i = 0; i < numEntries; i ++) {
        if (infos[i].dli_fname == NULL) {
            continue;
        }
        
        BugsnagStackframe *frame = [BugsnagStackframe new];
        frame.frameAddress = [NSNumber numberWithUnsignedLongLong:addresses[i]];
        frame.isPc = i == 0;
        frame.machoFile = [NSString stringWithUTF8String:infos[i].dli_fname];
        frame.machoLoadAddress = [NSNumber numberWithUnsignedLongLong:(uintptr_t)infos[i].dli_fbase];
        frame.method = [NSString stringWithUTF8String:infos[i].dli_sname];
        frame.symbolAddress = [NSNumber numberWithUnsignedLongLong:(uintptr_t)infos[i].dli_saddr];
        
        BSG_Mach_Header_Info *header = bsg_mach_headers_image_at_address(addresses[i]);
        if (header != NULL) {
            frame.machoVmAddress = [NSNumber numberWithUnsignedLongLong:header->imageVmAddr];
            if (header->uuid != NULL) {
                CFUUIDRef uuidRef = CFUUIDCreateFromUUIDBytes(NULL, *(CFUUIDBytes *)header->uuid);
                frame.machoUuid = (__bridge_transfer NSString *)CFUUIDCreateString(NULL, uuidRef);
                CFRelease(uuidRef);
            }
        }
        
        [frames addObject:frame];
    }
    
    free(addresses);
    free(infos);
    
    self.trace = frames;
    return self;
}

- (NSArray *)toArray {
    NSMutableArray *array = [NSMutableArray new];
    for (BugsnagStackframe *frame in self.trace) {
        [array addObject:[frame toDictionary]];
    }
    return array;
}

@end
