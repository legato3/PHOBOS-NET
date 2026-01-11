#!/bin/bash
# NetFlow Retention Script
# Cleans up nfdump files older than 7 days
# Can be run manually or via cron

NFDUMP_DIR="/var/cache/nfdump"
RETENTION_DAYS=7

# Calculate cutoff timestamp (7 days ago)
CUTOFF_DATE=$(date -d "${RETENTION_DAYS} days ago" +%Y%m%d 2>/dev/null || date -v-${RETENTION_DAYS}d +%Y%m%d 2>/dev/null)

if [ -z "$CUTOFF_DATE" ]; then
    # Fallback: use find with -mtime
    echo "Using find -mtime for cleanup..."
    find "$NFDUMP_DIR" -name "nfcapd.*" -type f -mtime +${RETENTION_DAYS} -delete
    DELETED=$(find "$NFDUMP_DIR" -name "nfcapd.*" -type f -mtime +${RETENTION_DAYS} | wc -l)
else
    echo "Cleaning up files older than $RETENTION_DAYS days (before $CUTOFF_DATE)..."
    # Delete files with date in filename older than cutoff
    DELETED=0
    for file in "$NFDUMP_DIR"/nfcapd.*; do
        if [ -f "$file" ]; then
            # Extract date from filename (nfcapd.YYYYMMDDHHMM)
            filename=$(basename "$file")
            filedate=$(echo "$filename" | sed -n 's/nfcapd\.\([0-9]\{8\}\).*/\1/p')
            if [ -n "$filedate" ] && [ "$filedate" -lt "$CUTOFF_DATE" ]; then
                rm -f "$file"
                ((DELETED++))
            fi
        fi
    done
fi

echo "Cleaned up $DELETED old NetFlow files"
echo "Current NetFlow directory size: $(du -sh $NFDUMP_DIR | cut -f1)"
