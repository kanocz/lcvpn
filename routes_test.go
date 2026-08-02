package main

import (
	"errors"
	"testing"
)

func TestReconcileRoutesRetriesFailedOperations(t *testing.T) {
	current := map[string]bool{}
	desired := map[string]bool{"10.0.0.0/8": true}
	addErr := errors.New("temporary add failure")
	deleteErr := errors.New("temporary delete failure")
	addCalls, deleteCalls := 0, 0
	addRoute := func(string) error {
		addCalls++
		if addCalls == 1 {
			return addErr
		}
		return nil
	}
	deleteRoute := func(string) error {
		deleteCalls++
		if deleteCalls == 1 {
			return deleteErr
		}
		return nil
	}

	reconcileRoutes(current, desired, addRoute, deleteRoute)
	if current["10.0.0.0/8"] {
		t.Fatal("failed add was recorded as successful")
	}
	reconcileRoutes(current, desired, addRoute, deleteRoute)
	if !current["10.0.0.0/8"] || addCalls != 2 {
		t.Fatalf("successful retry was not recorded: current=%v calls=%d", current, addCalls)
	}
	reconcileRoutes(current, desired, addRoute, deleteRoute)
	if addCalls != 2 {
		t.Fatalf("already applied route was added again; calls=%d", addCalls)
	}

	desired = map[string]bool{}
	reconcileRoutes(current, desired, addRoute, deleteRoute)
	if !current["10.0.0.0/8"] {
		t.Fatal("failed delete was removed from bookkeeping")
	}
	reconcileRoutes(current, desired, addRoute, deleteRoute)
	if current["10.0.0.0/8"] || deleteCalls != 2 {
		t.Fatalf("successful delete retry was not recorded: current=%v calls=%d", current, deleteCalls)
	}
}
