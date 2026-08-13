//
//  BlockOrAllowList.m
//  Extension
//
//  Created by Patrick Wardle on 11/6/20.
//  Copyright © 2020 Objective-See. All rights reserved.
//

#import "consts.h"
#import "Preferences.h"
#import "BlockOrAllowList.h"

/* GLOBALS */

//log handle
extern os_log_t logHandle;

//preferences
extern Preferences* preferences;

@implementation BlockOrAllowList

-(id)init:(NSString*)path
{
    //init super
    self = [super init];
    if(nil != self)
    {
        //save list
        self.path = path;
        
        //load
        [self load:self.path];
    }
    
    return self;
}

//was specified block list remote
// remote policy is deliberately restricted to well-formed HTTPS URLs
-(BOOL)isRemote
{
    NSURLComponents* components = [NSURLComponents componentsWithString:self.path];

    return (components.scheme.length != 0 &&
            [components.scheme caseInsensitiveCompare:@"https"] == NSOrderedSame &&
            components.host.length != 0);
}

//HTTP policy is vulnerable to network tampering.  Reject malformed HTTPS URLs
//as well, rather than accidentally treating them as a local path.
-(BOOL)isUnsupportedRemote
{
    NSURLComponents* components = [NSURLComponents componentsWithString:self.path];

    return (components.scheme.length != 0 &&
            ([components.scheme caseInsensitiveCompare:@"http"] == NSOrderedSame ||
            ([components.scheme caseInsensitiveCompare:@"https"] == NSOrderedSame &&
             NO == [self isRemote])));
}

//should reload
// checks file modification time
-(BOOL)shouldReload
{
    //flag
    BOOL shouldReload = NO;
    
    //current mod. time
    NSDate* modified = nil;
    
    //if it's remote
    // can't tell, so default to no
    if(YES == [self isRemote])
    {
        //bail
        goto bail;
    }

    //no (local) path?
    // nothing loaded, so nothing to reload
    if(0 == self.path.length)
    {
        //bail
        goto bail;
    }

    //get modified timestamp
    modified = [[NSFileManager.defaultManager attributesOfItemAtPath:self.path error:nil] objectForKey:NSFileModificationDate];

    //no timestamp?
    // file is gone/unreadable -> reload (to clear) if we still hold stale items
    // note: load: empties items, so this naturally fires just once (not per-flow)
    if(nil == modified)
    {
        //stale items to clear?
        if(0 != self.items.count)
        {
            //dbg msg
            os_log_debug(logHandle, "list file is missing/unreadable ...will reload to clear stale items");

            //yes
            shouldReload = YES;
        }

        //bail
        goto bail;
    }

    //was file modified?
    if(NSOrderedDescending == [modified compare:self.lastModified])
    {
        //dbg msg
        os_log_debug(logHandle, "block list was modified ...will reload");

        //yes
        shouldReload = YES;
    }
    
bail:
    
    return shouldReload;
}

//stop the daily (remote) reload timer, if any
-(void)stopReloadTimer
{
    if(nil != self.reloadTimer)
    {
        dispatch_source_cancel(self.reloadTimer);
        self.reloadTimer = nil;
    }
}

//arm a single reload timer; replacing an existing timer avoids duplicate
//background fetches when startup retries or preference changes overlap
-(void)armReloadTimerWithInitialDelay:(NSTimeInterval)initialDelay
                              interval:(NSTimeInterval)interval
{
    __weak typeof(self) weakSelf = self;

    [self stopReloadTimer];

    self.reloadTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                                               dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0));
    dispatch_source_set_timer(self.reloadTimer,
                              dispatch_time(DISPATCH_TIME_NOW, (int64_t)(initialDelay * NSEC_PER_SEC)),
                              (uint64_t)(interval * NSEC_PER_SEC),
                              (uint64_t)(MIN(interval / 10.0, 60.0) * NSEC_PER_SEC));
    dispatch_source_set_event_handler(self.reloadTimer, ^{
        [weakSelf load:weakSelf.path];
    });
    dispatch_resume(self.reloadTimer);
}

//clear the list
// empties items & stops any (remote) reload timer
-(void)clear
{
    //sync
    @synchronized (self) {

        //dbg msg
        os_log_debug(logHandle, "clearing list");

        //reset path
        self.path = @"";

        //reset list
        [self.items removeAllObjects];

        //reset timestamp
        self.lastModified = nil;
        self.lastLoaded = nil;
        self.lastError = nil;

        //stop any (remote) reload timer
        [self stopReloadTimer];
    }
}

//(re)load
-(BOOL)load:(NSString*)path
{
    //result
    BOOL loaded = NO;

    //error
    NSError* error = nil;
    
    //file contents
    NSString* list = nil;

    //changing sources is different from a transient refresh failure: retaining
    //a policy from the previous source would be surprising and unsafe.
    BOOL pathChanged = NO;
    
    //sync
    @synchronized (self) {
        
    pathChanged = (nil != self.path && NO == [self.path isEqualToString:path]);

    if(YES == pathChanged)
    {
        self.lastLoaded = nil;
        self.lastError = nil;
    }

    //update path
    self.path = path;
        
    //dbg msg
    os_log_debug(logHandle, "%s", __PRETTY_FUNCTION__);
    
    //check
    // path?
    if(0 == self.path.length)
    {
        //an explicitly cleared policy source means an empty policy
        [self.items removeAllObjects];
        self.lastLoaded = nil;
        self.lastError = nil;
        //dbg msg
        os_log_debug(logHandle, "no list specified...");

        //no remote list -> stop any reload timer
        [self stopReloadTimer];

        //nothing to load (success)
        loaded = YES;

        //bail
        goto bail;
    }

    //Never retrieve policy over plaintext HTTP. Invalid policy sources are
    //cleared so normal LuLu rule handling can continue without stale policy.
    if(YES == [self isUnsupportedRemote])
    {
        os_log_error(logHandle, "ERROR: rejecting unsupported remote list URL");
        [self.items removeAllObjects];
        self.lastError = @"Invalid remote URL";
        [self stopReloadTimer];
        goto bail;
    }
        
    //remote?
    // load via URL
    if(YES == [self isRemote])
    {
        //dbg msg
        os_log_debug(logHandle, "(re)loading (remote) list");
        
        //load
        list = [NSString stringWithContentsOfURL:[NSURL URLWithString:self.path] encoding:NSUTF8StringEncoding error:&error];
        if(nil != error)
        {
            //err msg
            os_log_error(logHandle, "ERROR: failed to (re)load (remote) list, %{private}@ (error: %{private}@)", self.path, error);

            //Preserve the last known-good policy during a transient refresh.
            //A newly configured source remains empty and falls back to normal
            //LuLu rule handling instead of disrupting all network traffic.
            if(YES == pathChanged)
            {
                [self.items removeAllObjects];
            }

            self.lastError = @"Remote list unavailable";

            //Continue trying in the background when the machine starts
            //offline or a policy service is temporarily unavailable. This
            //preserves normal LuLu usability without leaving a new policy
            //source permanently unloaded.
            [self armReloadTimerWithInitialDelay:(5 * 60) interval:(15 * 60)];

            //bail
            goto bail;
        }

        //A successful fetch returns to the normal low-frequency refresh.
        [self armReloadTimerWithInitialDelay:(24 * 60 * 60) interval:(24 * 60 * 60)];
    }
    
    //local file
    // check and load
    else
    {
        //dbg msg
        os_log_debug(logHandle, "(re)loading (local) list, %{private}@", self.path);

        //local (not remote) -> stop any reload timer
        [self stopReloadTimer];

        //A local policy path is authoritative.  Do not continue enforcing a
        //policy from a different, now-missing local file.
        [self.items removeAllObjects];

        //(re)load
        list = [NSString stringWithContentsOfFile:self.path encoding:NSUTF8StringEncoding error:&error];
        if(nil != error)
        {
            //err msg
            os_log_error(logHandle, "ERROR: failed to (re)load (local) list, %{private}@ (error: %{private}@)", self.path, error);
            self.lastError = @"Local list unavailable";
            
            //bail
            goto bail;
        }
        
        //save timestamp
        self.lastModified = [[NSFileManager.defaultManager attributesOfItemAtPath:self.path error:nil] objectForKey:NSFileModificationDate];
    }
    
    //init set
    // of trimmed/lower-cased items
    self.items = [NSMutableSet setWithArray:[[[list componentsSeparatedByString:@"\n"] filteredArrayUsingPredicate:[NSPredicate predicateWithBlock:^BOOL(NSString *item, NSDictionary *bindings) {
                //trim
                NSString* trimmed = [item stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
                
                //make sure its not empty/not a comment
                return (trimmed.length > 0 && ![trimmed hasPrefix:@"#"]);
        
            }]] valueForKey:@"lowercaseString"]];
        
    //dbg msg
    os_log_debug(logHandle, "(re)loaded %lu list items", (unsigned long)self.items.count);

    self.lastLoaded = NSDate.date;
    self.lastError = nil;

    //success
    loaded = YES;

    } //sync

bail:

    return loaded;
}

//return only presentation-safe runtime state; detailed errors remain private
//in Unified Logging
-(NSDictionary*)status
{
    NSMutableDictionary* status = nil;

    @synchronized (self) {
        status = [@{
            KEY_LIST_STATUS_PATH: self.path ?: @"",
            KEY_LIST_STATUS_REMOTE: @([self isRemote]),
            KEY_LIST_STATUS_ITEM_COUNT: @(self.items.count),
        } mutableCopy];

        if(nil != self.lastLoaded) status[KEY_LIST_STATUS_LAST_LOADED] = self.lastLoaded;
        if(0 != self.lastError.length) status[KEY_LIST_STATUS_ERROR] = self.lastError;
    }

    return status;
}

//check if flow matches item on block or allow list
// note: currently lists don't support port matching
-(BOOL)isMatch:(NEFilterSocketFlow*)flow
{
    //match
    BOOL isMatch = NO;
    
    //remote endpoint
    NWHostEndpoint* remoteEndpoint = nil;
    
    //endpoint url/hosts
    NSMutableSet* endpointNames = nil;
    
    //matches
    NSSet* matches = nil;
    
    //extract remote endpoint
    remoteEndpoint = (NWHostEndpoint*)flow.remoteEndpoint;
    
    //need to reload list?
    // checks timestamp to see if modified
    if(YES == [self shouldReload])
    {
        //(re)load list
        [self load:self.path];
    }
    
    //sync
    @synchronized (self) {
        
    //init endpoint names
    endpointNames = [NSMutableSet set];
        
    //add url
    if(nil != flow.URL.absoluteString)
    {
        //add full url
        [endpointNames addObject:flow.URL.absoluteString.lowercaseString];
    }
    
    //add host
    if(nil != flow.URL.host)
    {
        //add full url
        [endpointNames addObject:flow.URL.host.lowercaseString];
    }
        
    //add host name
    if(nil != remoteEndpoint.hostname)
    {
        //add
        [endpointNames addObject:remoteEndpoint.hostname.lowercaseString];
    }
    
    //macOS 11+?
    // add remote host name
    if(@available(macOS 11, *))
    {
        //add remote host name
        if(nil != flow.remoteHostname)
        {
            //add
            [endpointNames addObject:flow.remoteHostname.lowercaseString];
         
            //if it starts w/ 'www.'
            // strip and add that too
            if(YES == [flow.remoteHostname hasPrefix:@"www."])
            {
                //add
                [endpointNames addObject:[[flow.remoteHostname substringFromIndex:4] lowercaseString]];
            }
        }
    }
    
    //first check for "all"
    // for IPV4 -> '0.0.0.0/0'
    if( (AF_INET == flow.socketFamily) &&
        ([self.items containsObject:@"0.0.0.0/0"]) )
    {
        isMatch = YES;
        goto bail;
    }
    //for IPV6 -> '::/0'
    else if( (AF_INET6 == flow.socketFamily) &&
             ([self.items containsObject:@"::/0"]) )
    {
        isMatch = YES;
        goto bail;
    }
   
    //find matches
    matches = [self.items objectsPassingTest:^BOOL(NSString* item, BOOL* stop) {
        return [endpointNames containsObject:item];
    }];
        
    //any matches?
    if(0 != matches.count)
    {
        //dbg msg
        os_log_debug(logHandle, "endpoint names %{private}@ matched the following list items %{private}@", endpointNames, matches);
       
        //set flag
        isMatch = YES;
    }
        
    }//sync
    
bail:
    
    return isMatch;
}

@end
