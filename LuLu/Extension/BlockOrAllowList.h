//
//  BlockOrAllowList.h
//  Extension
//
//  Created by Patrick Wardle on 11/6/20.
//  Copyright © 2020 Objective-See. All rights reserved.
//

@import Cocoa;
@import OSLog;
@import NetworkExtension;

NS_ASSUME_NONNULL_BEGIN

@interface BlockOrAllowList : NSObject

/* PROPERTIES */

//path
@property(nonatomic, retain)NSString* path;

//block list
@property(nonatomic, retain)NSMutableSet* items;

//modification time
@property(nullable, nonatomic, retain)NSDate* lastModified;

//timer to (re)load a remote list daily
// note: a single repeating source, so reloads don't stack
@property(nullable, nonatomic, strong)dispatch_source_t reloadTimer;


/* METHODS */

//init
// with a path
-(id)init:(NSString*)path;

//(re)load from disk
// returns YES if the list loaded (or there's nothing to load); NO on a fetch/read failure
-(BOOL)load:(NSString*)path;

//clear the list
// empties items & stops any (remote) reload timer
-(void)clear;

//should reload
// checks file modification time
-(BOOL)shouldReload;

//check if flow matches item on block list
-(BOOL)isMatch:(NEFilterSocketFlow*)flow;

//current, non-persistent load status for the UI
-(NSDictionary*)status;

//time at which this source last loaded successfully
@property(nullable, nonatomic, retain)NSDate* lastLoaded;

//brief non-sensitive reason why the most recent load failed
@property(nullable, nonatomic, copy)NSString* lastError;

@end

NS_ASSUME_NONNULL_END
